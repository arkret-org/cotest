//! Closed decision-point evidence derived from canonical fixtures and actual executions.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use serde_json::Value;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CaseRef {
    pub fixture_ref: String,
    pub case_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionPointGap {
    pub decision_point: String,
    pub missing_cases: Vec<CaseRef>,
}

/// An execution is supplied only after its runner and fixture bijection pass.
/// Partial/harness evidence must be withheld by the caller, even when it ran.
/// Required refs are conjunctive; other points require one executed carrier.
pub fn audit_decision_points(
    profiles: &Value,
    fixtures: &BTreeMap<String, Value>,
    executed: &BTreeSet<CaseRef>,
) -> Result<Vec<DecisionPointGap>> {
    let mut carriers: BTreeMap<String, Vec<(CaseRef, BTreeSet<String>)>> = BTreeMap::new();
    for (fixture_ref, fixture) in fixtures {
        let vectors = match fixture.get("covers_vectors") {
            Some(value) => value
                .as_array()
                .context("fixture covers_vectors is not an array")?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .context("fixture vector is not a string")
                })
                .collect::<Result<BTreeSet<_>>>()?,
            None => BTreeSet::new(),
        };
        collect_cases(
            fixture,
            fixture_ref,
            &vectors,
            &mut carriers,
            &mut BTreeSet::new(),
        )?;
    }
    let clauses = profiles
        .pointer("/sdk_conformance_contract/clauses")
        .and_then(Value::as_array)
        .context("canonical SDK contract has no clauses[]")?;
    let mut gaps = Vec::new();
    let mut declared_points = BTreeSet::new();
    for clause in clauses {
        let clause_id = clause["clause_id"].as_str().context("clause has no id")?;
        let Some(points) = clause
            .pointer("/vector_evidence/decision_points")
            .and_then(Value::as_array)
        else {
            continue;
        };
        for point in points {
            let id = format!(
                "{clause_id}/{}",
                point["id"].as_str().context("decision point has no id")?
            );
            ensure!(
                declared_points.insert(id.clone()),
                "duplicate decision point {id}"
            );
            let vectors = point["vectors"]
                .as_array()
                .context("decision point has no vectors[]")?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .context("vector is not a string")
                })
                .collect::<Result<BTreeSet<_>>>()?;
            ensure!(!vectors.is_empty(), "{id} has no active vector");
            let candidates = carriers
                .get(&id)
                .context(format!("{id} has no canonical case carrier"))?;
            let eligible = candidates
                .iter()
                .filter(|(_, carried)| !vectors.is_disjoint(carried))
                .map(|(case, _)| case.clone())
                .collect::<BTreeSet<_>>();
            ensure!(
                !eligible.is_empty(),
                "{id} has no case carrying its active vector"
            );
            let missing = if let Some(refs) = point.get("required_case_refs") {
                let refs = refs
                    .as_array()
                    .context("required_case_refs is not an array")?;
                ensure!(!refs.is_empty(), "{id}: empty required_case_refs");
                let mut required = BTreeSet::new();
                for value in refs {
                    let case = CaseRef {
                        fixture_ref: value["fixture_ref"]
                            .as_str()
                            .context("case ref has no fixture_ref")?
                            .to_owned(),
                        case_id: value["case_id"]
                            .as_str()
                            .context("case ref has no case_id")?
                            .to_owned(),
                    };
                    ensure!(
                        eligible.contains(&case),
                        "{id}: required case {case:?} is not an eligible carrier"
                    );
                    ensure!(required.insert(case), "{id}: duplicate required case ref");
                }
                required.difference(executed).cloned().collect::<Vec<_>>()
            } else if eligible.is_disjoint(executed) {
                eligible.into_iter().collect()
            } else {
                Vec::new()
            };
            if !missing.is_empty() {
                gaps.push(DecisionPointGap {
                    decision_point: id,
                    missing_cases: missing,
                });
            }
        }
    }
    ensure!(
        carriers.keys().all(|id| declared_points.contains(id)),
        "fixture names a retired or unknown decision point"
    );
    gaps.sort_by(|a, b| a.decision_point.cmp(&b.decision_point));
    Ok(gaps)
}

fn collect_cases(
    node: &Value,
    fixture_ref: &str,
    vectors: &BTreeSet<String>,
    carriers: &mut BTreeMap<String, Vec<(CaseRef, BTreeSet<String>)>>,
    seen_names: &mut BTreeSet<String>,
) -> Result<()> {
    match node {
        Value::Object(object) => {
            if let Some(points) = object.get("covers_decision_points") {
                let name = node["name"]
                    .as_str()
                    .filter(|name| !name.trim().is_empty())
                    .context("decision-point case has no name")?;
                ensure!(
                    seen_names.insert(name.to_owned()),
                    "{fixture_ref}: ambiguous case name {name}"
                );
                let expected = node
                    .get("expected")
                    .context("decision-point case has no expected result")?;
                ensure!(
                    match expected {
                        Value::Object(object) => !object.is_empty(),
                        Value::Array(values) => !values.is_empty(),
                        Value::String(text) => !text.trim().is_empty(),
                        Value::Bool(_) | Value::Number(_) => true,
                        Value::Null => false,
                    },
                    "{name}: empty expected result"
                );
                let points = points
                    .as_array()
                    .context("covers_decision_points is not an array")?;
                ensure!(!points.is_empty(), "{name}: empty covers_decision_points");
                let mut unique = BTreeSet::new();
                for point in points {
                    let id = point
                        .as_str()
                        .context("decision point ref is not a string")?;
                    ensure!(unique.insert(id), "{name}: duplicate decision point {id}");
                    let case = CaseRef {
                        fixture_ref: fixture_ref.to_owned(),
                        case_id: name.to_owned(),
                    };
                    let rows = carriers.entry(id.to_owned()).or_default();
                    ensure!(
                        !rows.iter().any(|(prior, _)| prior == &case),
                        "duplicate case {case:?}"
                    );
                    rows.push((case, vectors.clone()));
                }
            }
            for child in object.values() {
                collect_cases(child, fixture_ref, vectors, carriers, seen_names)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_cases(child, fixture_ref, vectors, carriers, seen_names)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn inputs() -> (Value, BTreeMap<String, Value>, CaseRef, CaseRef) {
        let first = CaseRef {
            fixture_ref: "fixtures/test.json".into(),
            case_id: "first".into(),
        };
        let second = CaseRef {
            fixture_ref: first.fixture_ref.clone(),
            case_id: "second".into(),
        };
        let profiles = json!({"sdk_conformance_contract":{"clauses":[{"clause_id":"AK-SDK-001","vector_evidence":{"decision_points":[{
            "id":"point", "vectors":["vector"], "required_case_refs":[
                {"fixture_ref":first.fixture_ref,"case_id":first.case_id},
                {"fixture_ref":second.fixture_ref,"case_id":second.case_id}
            ]
        }]}}]}});
        let fixture = json!({"covers_vectors":["vector"],"cases":[
            {"name":"first","expected":{"decision":"reject"},"covers_decision_points":["AK-SDK-001/point"]},
            {"name":"second","expected":{"decision":"accept"},"covers_decision_points":["AK-SDK-001/point"]}
        ]});
        (
            profiles,
            BTreeMap::from([(first.fixture_ref.clone(), fixture)]),
            first,
            second,
        )
    }

    #[test]
    fn required_cases_are_conjunctive_and_drift_is_rejected() -> Result<()> {
        let (mut profiles, fixtures, first, second) = inputs();
        let executed = BTreeSet::from([first]);
        let gaps = audit_decision_points(&profiles, &fixtures, &executed)?;
        assert_eq!(gaps[0].missing_cases, vec![second.clone()]);
        assert!(
            audit_decision_points(
                &profiles,
                &fixtures,
                &executed.union(&BTreeSet::from([second])).cloned().collect()
            )?
            .is_empty()
        );
        profiles["sdk_conformance_contract"]["clauses"][0]["vector_evidence"]["decision_points"]
            [0]["required_case_refs"][1]["case_id"] = json!("renamed");
        assert!(audit_decision_points(&profiles, &fixtures, &executed).is_err());
        Ok(())
    }

    #[test]
    fn wrong_vector_and_duplicate_refs_do_not_count() {
        let (mut profiles, mut fixtures, first, _) = inputs();
        fixtures.get_mut(&first.fixture_ref).unwrap()["covers_vectors"] = json!(["unrelated"]);
        assert!(audit_decision_points(&profiles, &fixtures, &BTreeSet::new()).is_err());
        let (_, fixtures, ..) = inputs();
        let refs = &mut profiles["sdk_conformance_contract"]["clauses"][0]["vector_evidence"]["decision_points"]
            [0]["required_case_refs"];
        refs[1] = refs[0].clone();
        assert!(audit_decision_points(&profiles, &fixtures, &BTreeSet::new()).is_err());
    }

    #[test]
    fn ambiguous_case_names_and_malformed_vector_declarations_are_rejected() {
        let (mut profiles, mut fixtures, first, _) = inputs();
        let points = profiles["sdk_conformance_contract"]["clauses"][0]["vector_evidence"]["decision_points"].as_array_mut().unwrap();
        points[0]["required_case_refs"]
            .as_array_mut()
            .unwrap()
            .truncate(1);
        points.push(json!({"id":"other", "vectors":["vector"]}));
        let second = &mut fixtures.get_mut(&first.fixture_ref).unwrap()["cases"][1];
        second["name"] = json!("first");
        second["covers_decision_points"] = json!(["AK-SDK-001/other"]);
        assert!(audit_decision_points(&profiles, &fixtures, &BTreeSet::new()).is_err());
        let (profiles, mut fixtures, first, _) = inputs();
        fixtures.get_mut(&first.fixture_ref).unwrap()["covers_vectors"] = json!(["vector", 7]);
        assert!(audit_decision_points(&profiles, &fixtures, &BTreeSet::new()).is_err());
    }

    #[test]
    fn canonical_contract_produces_explicit_gaps_without_executions() -> Result<()> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../arkret-spec/spec/v1/artifacts");
        let profiles = serde_json::from_slice(&std::fs::read(
            root.join("profiles/conformance-profiles.json"),
        )?)?;
        let mut fixtures = BTreeMap::new();
        for entry in std::fs::read_dir(root.join("fixtures"))? {
            let path = entry?.path();
            if path.extension().and_then(|x| x.to_str()) == Some("json") {
                fixtures.insert(
                    format!("fixtures/{}", path.file_name().unwrap().to_string_lossy()),
                    serde_json::from_slice(&std::fs::read(path)?)?,
                );
            }
        }
        let gaps = audit_decision_points(&profiles, &fixtures, &BTreeSet::new())?;
        assert!(!gaps.is_empty());
        assert!(gaps.iter().all(|gap| !gap.missing_cases.is_empty()));
        Ok(())
    }
}

# Service Resolution Bootstrap

## Intent

Prove the live Principal Server publishes a self-contained signed current route
record and that the record is reverse-bound to the role-scoped
`ServiceDescribe` selected at its advertised HTTPS base URL.

This scenario covers only current-route authentication and stable refresh
inside the record's refresh window. It does not claim planned handover,
outbound peer publication, ACK barriers, candidate cutover, or Realm-mirror
recovery coverage.

## Strand

1. Read `/_arkret/describe?service_kind=principal_server`.
2. Fetch the exact advertised service core from
   `/_arkret/open/services/{service_id}/resolution` without redirects.
3. Cross-check service core, DID, method-history head, version, role,
   canonical base URL, and the registered Describe projection digest.
4. Confirm the record proof names an assertion method in the returned
   normalized DID document and the time window is ordered.
5. Fetch the same URL again inside `refresh_after` and require the complete
   authenticated response to remain byte-equivalent as parsed JSON.
6. Query the same endpoint with another service core and require an opaque
   not-found response.

## Acceptance

- A bare URL, redirect, or a record for another service core cannot become a
  route.
- Current record and Describe agree on all reverse-binding coordinates.
- Re-reading a fresh current record does not consume a new sequence.
- No assertion in this scenario is counted as handover or lost-route recovery
  evidence.

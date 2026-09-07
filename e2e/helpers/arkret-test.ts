import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  test as playwrightTest,
  type APIRequestContext,
} from "@playwright/test";

export * from "@playwright/test";

import { publicRequestFailure } from "./secret-safe";

type RegisteredHttpOperation = {
  operationId: string;
  method: string;
  pathPattern: RegExp;
};

const helperDir = dirname(fileURLToPath(import.meta.url));
const operationRegistryPath = resolve(
  helperDir,
  "../../../arkret-spec/spec/v1/artifacts/registry/operation-registry.json",
);
const operationRegistry = JSON.parse(readFileSync(operationRegistryPath, "utf8")) as {
  operations: Array<{ operation_id: string; http?: string }>;
};

const registeredHttpOperations = operationRegistry.operations.flatMap(
  (operation): RegisteredHttpOperation[] => {
    if (!operation.http) return [];
    const separator = operation.http.indexOf(" ");
    if (separator < 1) return [];
    const method = operation.http.slice(0, separator).toUpperCase();
    const pathTemplate = operation.http.slice(separator + 1);
    const escaped = pathTemplate.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const pathPattern = new RegExp(
      `^${escaped.replace(/\\\{[^}]+\\\}/g, "[^/]+")}$`,
    );
    return [{ operationId: operation.operation_id, method, pathPattern }];
  },
);

export function operationSelector(method: string, url: string): string | undefined {
  const pathname = new URL(url, "http://cotest.invalid").pathname;
  return registeredHttpOperations.find(
    (operation) =>
      operation.method === method && operation.pathPattern.test(pathname),
  )?.operationId;
}

export function withOperationSelectors(
  request: APIRequestContext,
): APIRequestContext {
  const methods = new Set(["delete", "get", "head", "patch", "post", "put"]);
  return new Proxy(request, {
    get(target, property, receiver) {
      if (property === "fetch") {
        return async (url: string, options: Record<string, unknown> = {}) => {
          const call = Reflect.get(target, property, target) as (
            url: string,
            options?: Record<string, unknown>,
          ) => Promise<unknown>;
          const method =
            typeof options.method === "string" ? options.method.toUpperCase() : "GET";
          const selector = operationSelector(method, url);
          const headers = {
            ...((options.headers as Record<string, string> | undefined) ?? {}),
          };
          if (selector &&
            !Object.keys(headers).some(
              (name) => name.toLowerCase() === "arkret-operation",
            )
          ) {
            headers["Arkret-Operation"] = selector;
          }
          try {
            return await call.call(target, url, { ...options, headers });
          } catch (error) {
            throw publicRequestFailure(error, method, selector);
          }
        };
      }
      if (typeof property !== "string" || !methods.has(property)) {
        const value = Reflect.get(target, property, receiver);
        return typeof value === "function" ? value.bind(target) : value;
      }
      return async (url: string, options: Record<string, unknown> = {}) => {
        const call = Reflect.get(target, property, target) as (
          url: string,
          options?: Record<string, unknown>,
        ) => Promise<unknown>;
        const selector = operationSelector(property.toUpperCase(), url);
        const headers = {
          ...((options.headers as Record<string, string> | undefined) ?? {}),
        };
        if (selector &&
          !Object.keys(headers).some(
            (name) => name.toLowerCase() === "arkret-operation",
          )
        ) {
          headers["Arkret-Operation"] = selector;
        }
        try {
          return await call.call(target, url, { ...options, headers });
        } catch (error) {
          throw publicRequestFailure(error, property.toUpperCase(), selector);
        }
      };
    },
  });
}

export const test = playwrightTest.extend({
  request: async ({ request }, use) => {
    await use(withOperationSelectors(request));
  },
});

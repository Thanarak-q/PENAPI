// GraphQL Toolkit — pure, DOM-free core. Provides copyable probe queries for
// authorized GraphQL testing and an introspection JSON parser that surfaces root
// types, available query/mutation fields, and all named types. DOM-free for
// `node --test`.

/**
 * Six probes useful during an authorized GraphQL engagement.
 * Returns an array of { label, query } objects.
 */
export function commonProbes() {
  return [
    {
      label: 'Full introspection',
      query:
        'query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name kind description fields(includeDeprecated:true){name description args{name description type{name kind ofType{name kind}}}type{name kind ofType{name kind}}isDeprecated deprecationReason}inputFields{name}interfaces{name}enumValues(includeDeprecated:true){name}possibleTypes{name}}directives{name description locations args{name description type{name kind ofType{name kind}}}}}}',
    },
    {
      label: 'Typename probe (minimal)',
      query: '{__typename}',
    },
    {
      label: 'Query root name',
      query: '{__schema{queryType{name}}}',
    },
    {
      label: 'All type names',
      query: '{__schema{types{name}}}',
    },
    {
      label: 'Field suggestion typo probe',
      query: '{usr{id}}',
    },
    {
      label: 'Batch query (body — array of two queries)',
      query: '[{"query":"{__typename}"},{"query":"{__typename}"}]',
    },
  ];
}

/**
 * Parse a GraphQL introspection JSON response.
 * Accepts both the full { "data": { "__schema": {...} } } envelope and the bare
 * { "__schema": {...} } form. Filters out types whose names start with "__".
 *
 * Returns {
 *   ok, error,
 *   queryType, mutationType, subscriptionType,  — root type NAMES or null
 *   types: [{ name, kind, fieldCount, fields }]  — non-introspection types
 * }
 * Never throws.
 */
export function parseIntrospection(jsonText) {
  let data;
  try {
    data = JSON.parse(String(jsonText || ''));
  } catch (e) {
    return {
      ok: false,
      error: e.message,
      queryType: null,
      mutationType: null,
      subscriptionType: null,
      types: [],
    };
  }

  // Accept { data: { __schema } } or { __schema }
  const schema =
    (data && data.data && data.data.__schema) ||
    (data && data.__schema) ||
    null;

  if (!schema) {
    return {
      ok: false,
      error: 'No __schema found in response',
      queryType: null,
      mutationType: null,
      subscriptionType: null,
      types: [],
    };
  }

  const queryType = (schema.queryType && schema.queryType.name) || null;
  const mutationType = (schema.mutationType && schema.mutationType.name) || null;
  const subscriptionType = (schema.subscriptionType && schema.subscriptionType.name) || null;

  const rawTypes = Array.isArray(schema.types) ? schema.types : [];
  const types = rawTypes
    .filter((t) => t && typeof t.name === 'string' && !t.name.startsWith('__'))
    .map((t) => {
      const fieldArr = Array.isArray(t.fields) ? t.fields : [];
      return {
        name: t.name,
        kind: t.kind || 'UNKNOWN',
        fieldCount: fieldArr.length,
        fields: fieldArr.map((f) => f && f.name).filter(Boolean),
      };
    });

  return {
    ok: true,
    error: null,
    queryType,
    mutationType,
    subscriptionType,
    types,
  };
}

/**
 * Given a successful parseIntrospection result, return field names on the
 * query and mutation root types.
 * Returns { queries: [string], mutations: [string] }.
 * Returns empty arrays if the root types are not resolvable.
 */
export function extractOperations(parsed) {
  if (!parsed || !parsed.ok) return { queries: [], mutations: [] };

  const findFields = (typeName) => {
    if (!typeName) return [];
    const t = (parsed.types || []).find((x) => x.name === typeName);
    return t ? t.fields : [];
  };

  return {
    queries: findFields(parsed.queryType),
    mutations: findFields(parsed.mutationType),
  };
}

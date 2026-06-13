'use strict';

// Parses an OpenAPI / Swagger document into a normalized endpoint list.
// Supports Swagger 2.0 and OpenAPI 3.x. Resolves local $ref pointers and
// synthesizes example request bodies. Runs entirely server-side.

const MAX_REF_DEPTH = 12;

function resolveRef(root, ref) {
  if (typeof ref !== 'string' || !ref.startsWith('#/')) return undefined;
  const parts = ref.slice(2).split('/').map(decodePointer);
  let node = root;
  for (const p of parts) {
    if (node == null) return undefined;
    node = node[p];
  }
  return node;
}

function decodePointer(token) {
  return token.replace(/~1/g, '/').replace(/~0/g, '~');
}

// Build a representative example value from a JSON schema.
function exampleFromSchema(root, schema, depth, seen) {
  if (depth > MAX_REF_DEPTH || schema == null) return null;
  if (schema.$ref) {
    if (seen.has(schema.$ref)) return {};
    const next = new Set(seen);
    next.add(schema.$ref);
    return exampleFromSchema(root, resolveRef(root, schema.$ref), depth + 1, next);
  }
  if (schema.example !== undefined) return schema.example;
  if (schema.default !== undefined) return schema.default;
  if (Array.isArray(schema.enum) && schema.enum.length) return schema.enum[0];

  const composite = schema.allOf || schema.anyOf || schema.oneOf;
  if (composite && composite.length) {
    if (schema.allOf) {
      const merged = {};
      for (const sub of schema.allOf) {
        const v = exampleFromSchema(root, sub, depth + 1, seen);
        if (v && typeof v === 'object' && !Array.isArray(v)) Object.assign(merged, v);
      }
      return merged;
    }
    return exampleFromSchema(root, composite[0], depth + 1, seen);
  }

  const type = schema.type || (schema.properties ? 'object' : undefined);
  switch (type) {
    case 'object': {
      const obj = {};
      const props = schema.properties || {};
      for (const key of Object.keys(props)) {
        obj[key] = exampleFromSchema(root, props[key], depth + 1, seen);
      }
      return obj;
    }
    case 'array':
      return [exampleFromSchema(root, schema.items || {}, depth + 1, seen)];
    case 'integer':
    case 'number':
      return schema.format === 'int64' ? 0 : 0;
    case 'boolean':
      return false;
    case 'string': {
      if (schema.format === 'date-time') return '2025-01-01T00:00:00Z';
      if (schema.format === 'date') return '2025-01-01';
      if (schema.format === 'uuid') return '00000000-0000-0000-0000-000000000000';
      if (schema.format === 'email') return 'test@example.com';
      return 'string';
    }
    default:
      if (schema.properties) {
        const obj = {};
        for (const key of Object.keys(schema.properties)) {
          obj[key] = exampleFromSchema(root, schema.properties[key], depth + 1, seen);
        }
        return obj;
      }
      return null;
  }
}

function detectVersion(doc) {
  if (doc.openapi && /^3\./.test(doc.openapi)) return 3;
  if (doc.swagger && /^2\./.test(doc.swagger)) return 2;
  return doc.paths ? 3 : 0;
}

function baseUrlsV3(doc) {
  if (!Array.isArray(doc.servers) || !doc.servers.length) return [''];
  return doc.servers.map((s) => {
    let url = s.url || '';
    if (s.variables) {
      for (const [k, v] of Object.entries(s.variables)) {
        url = url.replace(new RegExp(`\\{${k}\\}`, 'g'), v.default ?? '');
      }
    }
    return url;
  });
}

function baseUrlV2(doc) {
  const scheme = (doc.schemes && doc.schemes[0]) || 'https';
  const host = doc.host || '';
  const basePath = doc.basePath || '';
  if (!host) return basePath || '';
  return `${scheme}://${host}${basePath}`;
}

function normalizeParams(root, params, version) {
  const out = { path: [], query: [], header: [], cookie: [], body: null };
  if (!Array.isArray(params)) return out;
  for (let p of params) {
    if (p && p.$ref) p = resolveRef(root, p.$ref) || p;
    if (!p || !p.in) continue;
    if (version === 2 && p.in === 'body') {
      out.body = {
        contentType: 'application/json',
        example: p.schema ? exampleFromSchema(root, p.schema, 0, new Set()) : null,
        required: !!p.required,
      };
      continue;
    }
    const entry = {
      name: p.name,
      required: !!p.required,
      description: p.description || '',
      schema: p.schema || { type: p.type },
      example:
        p.example !== undefined
          ? p.example
          : p.schema
          ? exampleFromSchema(root, p.schema, 0, new Set())
          : scalarExample(p),
    };
    if (out[p.in]) out[p.in].push(entry);
  }
  return out;
}

function scalarExample(p) {
  if (Array.isArray(p.enum) && p.enum.length) return p.enum[0];
  if (p.default !== undefined) return p.default;
  switch (p.type) {
    case 'integer':
    case 'number':
      return 0;
    case 'boolean':
      return false;
    default:
      return '';
  }
}

function requestBodyV3(root, op) {
  let rb = op.requestBody;
  if (!rb) return null;
  if (rb.$ref) rb = resolveRef(root, rb.$ref) || rb;
  const content = rb.content || {};
  const ct =
    content['application/json'] ? 'application/json' : Object.keys(content)[0];
  if (!ct) return null;
  const media = content[ct] || {};
  return {
    contentType: ct,
    example:
      media.example !== undefined
        ? media.example
        : media.schema
        ? exampleFromSchema(root, media.schema, 0, new Set())
        : null,
    required: !!rb.required,
  };
}

function securitySchemes(doc, version) {
  const out = {};
  const defs =
    version === 3
      ? (doc.components && doc.components.securitySchemes) || {}
      : doc.securityDefinitions || {};
  for (const [name, def] of Object.entries(defs)) {
    out[name] = {
      type: def.type,
      scheme: def.scheme,
      in: def.in,
      name: def.name,
      bearerFormat: def.bearerFormat,
      flows: def.flows,
    };
  }
  return out;
}

const METHODS = ['get', 'put', 'post', 'delete', 'patch', 'options', 'head', 'trace'];

function parseSpec(doc) {
  const version = detectVersion(doc);
  if (!version) throw new Error('Unrecognized spec: missing openapi/swagger version and paths');

  const baseUrls =
    version === 3 ? baseUrlsV3(doc) : [baseUrlV2(doc)];

  const endpoints = [];
  const paths = doc.paths || {};
  for (const path of Object.keys(paths)) {
    const item = paths[path] || {};
    const sharedParams = item.parameters || [];
    for (const method of METHODS) {
      const op = item[method];
      if (!op) continue;
      const merged = [...sharedParams, ...(op.parameters || [])];
      const params = normalizeParams(doc, merged, version);
      const body =
        version === 3 ? requestBodyV3(doc, op) : params.body;
      endpoints.push({
        id: `${method.toUpperCase()} ${path}`,
        method: method.toUpperCase(),
        path,
        operationId: op.operationId || '',
        summary: op.summary || '',
        description: op.description || '',
        tags: op.tags && op.tags.length ? op.tags : ['default'],
        deprecated: !!op.deprecated,
        params: {
          path: params.path,
          query: params.query,
          header: params.header,
          cookie: params.cookie,
        },
        body,
        security: op.security || doc.security || [],
      });
    }
  }

  return {
    title: (doc.info && doc.info.title) || 'API',
    version: (doc.info && doc.info.version) || '',
    specVersion: version === 3 ? doc.openapi : doc.swagger,
    baseUrls,
    securitySchemes: securitySchemes(doc, version),
    endpoints,
    tags: [...new Set(endpoints.flatMap((e) => e.tags))].sort(),
    stats: {
      endpoints: endpoints.length,
      paths: Object.keys(paths).length,
    },
  };
}

module.exports = { parseSpec, exampleFromSchema, resolveRef };

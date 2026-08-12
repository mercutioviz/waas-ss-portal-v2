'use strict';
/**
 * Config Transformer — pure client-side logic as a CommonJS module.
 *
 * This is a verbatim copy of the functions embedded in
 * app/templates/applications/config_transformer.html ({% block extra_js %}).
 * Keep the two in sync when the template changes.
 *
 * Usage:
 *   const { SECTION_DEFINITIONS, STRIP_CONSTANTS } = require('./constants.json');
 *   const ct = require('./config_transformer')(SECTION_DEFINITIONS, STRIP_CONSTANTS);
 *   const sections = ct.buildSectionMetadata(parsedJson);
 *   const result   = ct.doTransform(parsedJson, selections);
 */
module.exports = function createTransformer(SECTION_DEFINITIONS, STRIP_CONSTANTS) {

  // -------------------------------------------------------------------------
  // buildSectionMetadata — mirrors Python get_section_metadata()
  // -------------------------------------------------------------------------
  function buildSectionMetadata(parsed) {
    const result = [];
    for (const defn of SECTION_DEFINITIONS) {
      const key = defn.key;
      if (!(key in parsed)) continue;
      const sectionData = parsed[key];
      const meta = {
        key,
        label:            defn.label,
        type:             defn.type,
        description:      defn.description,
        always_strip_note: defn.always_strip_note || null,
      };

      if (defn.type === 'endpoints') {
        meta.sub_sections = (defn.sub_sections || []).map(sub => {
          let present = sub.key in sectionData;
          if (sub.key === 'sni_certificates') {
            present = !!(sectionData.sni_certificates && sectionData.sni_certificates.length);
          }
          return {
            key:     sub.key,
            label:   sub.label,
            caution: !!sub.caution,
            note:    sub.note    || null,
            warning: sub.warning || null,
            present,
          };
        });

      } else if (defn.type === 'named_list') {
        const items = Array.isArray(sectionData) ? sectionData : [];
        meta.count = items.length;
        meta.items = items.map((item, i) => ({
          id:    item[defn.id_field] != null ? String(item[defn.id_field]) : String(i),
          label: item[defn.id_field] != null ? String(item[defn.id_field]) : `Item ${i}`,
        }));

      } else if (defn.type === 'ip_list') {
        const items = Array.isArray(sectionData) ? sectionData : [];
        const labelFields = defn.label_fields || [defn.id_field];
        meta.count = items.length;
        meta.items = items.map((item, i) => ({
          id:    item[defn.id_field] != null ? String(item[defn.id_field]) : String(i),
          label: joinLabel(item, labelFields),
        }));

      } else if (defn.type === 'subsection') {
        const inner = (
          typeof sectionData === 'object' && sectionData !== null && !Array.isArray(sectionData)
        ) ? (sectionData[defn.list_field] || []) : [];
        const labelFields = defn.label_fields || [defn.id_field];
        meta.count     = inner.length;
        meta.list_field = defn.list_field;
        meta.items = inner.map((item, i) => ({
          id:    item[defn.id_field] != null ? String(item[defn.id_field]) : String(i),
          label: joinLabel(item, labelFields),
        }));

      } else if (defn.type === 'simple') {
        meta.count = null;
      }

      result.push(meta);
    }
    return result;
  }

  // -------------------------------------------------------------------------
  // joinLabel — mirrors Python _join_label()
  // -------------------------------------------------------------------------
  function joinLabel(item, fields) {
    const parts = (fields || [])
      .map(f => item[f])
      .filter(v => v !== undefined && v !== null && v !== '');
    return parts.slice(0, 2).join(' — ') || '(unnamed)';
  }

  // -------------------------------------------------------------------------
  // doTransform — mirrors Python transform_config()
  // -------------------------------------------------------------------------
  function doTransform(parsed, selections) {
    const result = {};
    for (const defn of SECTION_DEFINITIONS) {
      const key = defn.key;
      if (!(key in parsed)) continue;
      const sel = selections[key] || {};
      if (!sel.include) continue;
      const sectionData = parsed[key];

      if (defn.type === 'simple') {
        result[key] = sectionData;

      } else if (defn.type === 'named_list') {
        let items = Array.isArray(sectionData) ? sectionData : [];
        items = filterItems(items, defn.id_field, sel.items !== undefined ? sel.items : null);
        const strip = new Set(STRIP_CONSTANTS.server_runtime);
        result[key] = items.map(item => {
          const copy = {};
          for (const [k, v] of Object.entries(item)) { if (!strip.has(k)) copy[k] = v; }
          return copy;
        });

      } else if (defn.type === 'ip_list') {
        const items = Array.isArray(sectionData) ? sectionData : [];
        result[key] = filterItems(items, defn.id_field, sel.items !== undefined ? sel.items : null);

      } else if (defn.type === 'subsection') {
        if (typeof sectionData !== 'object' || sectionData === null || Array.isArray(sectionData)) {
          result[key] = sectionData;
        } else {
          const copy = Object.assign({}, sectionData);
          const selectedItems = sel.items !== undefined ? sel.items : null;
          if (defn.list_field in copy && selectedItems !== null) {
            copy[defn.list_field] = filterItems(copy[defn.list_field] || [], defn.id_field, selectedItems);
          }
          result[key] = copy;
        }

      } else if (defn.type === 'endpoints') {
        const ep = transformEndpoints(sectionData, sel.sub || {});
        if (Object.keys(ep).length > 0) result[key] = ep;
      }
    }
    return result;
  }

  // -------------------------------------------------------------------------
  // filterItems — mirrors Python _filter_items()
  // -------------------------------------------------------------------------
  function filterItems(items, idField, selectedIds) {
    if (selectedIds === null || selectedIds === undefined) return items;
    const selectedSet = new Set(selectedIds.map(String));
    return items.filter(item =>
      item[idField] !== undefined && selectedSet.has(String(item[idField]))
    );
  }

  // -------------------------------------------------------------------------
  // transformEndpoints — mirrors Python _transform_endpoints()
  // -------------------------------------------------------------------------
  function transformEndpoints(ep, sub) {
    const result = {};
    if (sub.https      && 'https'      in ep) result.https      = ep.https;
    if (sub.advanced   && 'advanced'   in ep) result.advanced   = ep.advanced;
    if (sub.deployment && 'deployment' in ep) result.deployment = ep.deployment;
    if (sub.domains    && 'domains'    in ep) result.domains    = ep.domains;
    if (sub.sni_certificates && ep.sni_certificates && ep.sni_certificates.length) {
      result.sni_certificates = ep.sni_certificates;
    }

    if (sub.ports && 'ports' in ep) {
      const strip = new Set(STRIP_CONSTANTS.endpoint_port);
      result.ports = (ep.ports || []).map(port => {
        const copy = {};
        for (const [k, v] of Object.entries(port)) { if (!strip.has(k)) copy[k] = v; }
        return copy;
      });
    }

    if (sub.certificate && 'certificate' in ep) {
      const strip = new Set(STRIP_CONSTANTS.endpoint_cert);
      const cert = {};
      for (const [k, v] of Object.entries(ep.certificate)) { if (!strip.has(k)) cert[k] = v; }
      result.certificate = cert;
    }

    return result;
  }

  return { buildSectionMetadata, doTransform, filterItems, transformEndpoints, joinLabel };
};

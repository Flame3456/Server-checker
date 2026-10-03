'use strict';

const { getSignatures } = require('./signatures');

function findSignaturesIn(rawText) {
  if (!rawText) return [];
  const text = String(rawText).toLowerCase();
  const found = [];

  for (const sig of getSignatures()) {
    const needle = sig.name.toLowerCase();
    if (!needle) continue;

    if (sig.distinctive) {
      if (text.includes(needle)) found.push(sig);
    } else {
      
      const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const re = new RegExp(`(^|[^a-z0-9а-я])${escaped}([^a-z0-9а-я]|$)`, 'i');
      if (re.test(text)) found.push(sig);
    }
  }
  return found;
}

module.exports = { findSignaturesIn };

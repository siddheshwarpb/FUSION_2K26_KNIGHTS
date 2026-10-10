const assert = require('assert');
const _ = require('lodash');

console.log("Running demo app test suite...");

// Test 1: Lodash functionality
const base = { a: 1, b: { c: 2 } };
const patch = { b: { d: 3 } };
const merged = _.merge({}, base, patch);
assert.strictEqual(merged.a, 1);
assert.strictEqual(merged.b.c, 2);
assert.strictEqual(merged.b.d, 3);
console.log("✓ Test 1: Lodash object merge passed");

// Test 2: Prototype pollution defense check
const payload = JSON.parse('{"__proto__": {"polluted": "yes"}}');
_.merge({}, payload);
assert.strictEqual(Object.prototype.polluted, undefined, "Prototype pollution detected!");
console.log("✓ Test 2: Object prototype integrity maintained");

console.log("All demo app unit tests passed successfully!");
process.exit(0);


// Regenerates javascript/obfuscator-*.js: one benign script transformed by javascript-obfuscator 4.1.1 (obfuscator.io) with its
// presets and its string-array, wrapper, control-flow and dead-code options, seed 20261016. Run: node generate-obfuscator.js
// CORVUS_FIXTURE_JS_OBFUSCATOR: a folder where javascript-obfuscator@4.1.1 is installed (node_modules inside). The outputs are text only.
const path = require('path');
const fs = require('fs');
const root = process.env.CORVUS_FIXTURE_JS_OBFUSCATOR;
if (!root) throw new Error('set CORVUS_FIXTURE_JS_OBFUSCATOR to the folder holding node_modules/javascript-obfuscator');
const JavaScriptObfuscator = require(path.join(root, 'node_modules', 'javascript-obfuscator'));
const out = path.join(__dirname, 'javascript');
fs.mkdirSync(out, { recursive: true });
const source = `
function report(target) {
    var message = 'corvus marker';
    var url = 'http://example.com/corvus/stage.txt';
    console.log(message + ' ' + target);
    return fetch(url, { method: 'POST', body: JSON.stringify({ host: target }) });
}
function pick(list) {
    var total = 0;
    for (var i = 0; i < list.length; i++) { total += list[i].length; }
    if (total > 10) { return 'long'; } else { return 'short'; }
}
report(pick(['alpha', 'beta', 'gamma']));
`;
const base = { seed: 20261016, target: 'browser' };
const cases = {
  'default': {},
  'preset-low': { optionsPreset: 'low-obfuscation' },
  'preset-medium': { optionsPreset: 'medium-obfuscation' },
  'preset-high': { optionsPreset: 'high-obfuscation', debugProtection: false, selfDefending: false, disableConsoleOutput: false },
  'strings-none': { stringArray: true, stringArrayThreshold: 1, stringArrayEncoding: [], stringArrayRotate: true },
  'strings-base64': { stringArray: true, stringArrayThreshold: 1, stringArrayEncoding: ['base64'], stringArrayRotate: true, stringArrayShuffle: true },
  'strings-rc4': { stringArray: true, stringArrayThreshold: 1, stringArrayEncoding: ['rc4'], stringArrayRotate: true, stringArrayShuffle: true },
  'strings-wrappers-function': { stringArray: true, stringArrayThreshold: 1, stringArrayEncoding: ['base64'], stringArrayWrappersCount: 2, stringArrayWrappersType: 'function', stringArrayWrappersParametersMaxCount: 5, stringArrayWrappersChainedCalls: true },
  'strings-calls-transform': { stringArray: true, stringArrayThreshold: 1, stringArrayEncoding: ['rc4'], stringArrayCallsTransform: true, stringArrayCallsTransformThreshold: 1, stringArrayIndexesType: ['hexadecimal-numeric-string'] },
  'control-flow': { controlFlowFlattening: true, controlFlowFlatteningThreshold: 1, stringArray: false },
  'control-flow-strings': { controlFlowFlattening: true, controlFlowFlatteningThreshold: 1, stringArray: true, stringArrayThreshold: 1, stringArrayEncoding: ['base64'], splitStrings: true, splitStringsChunkLength: 4 },
  'dead-code': { deadCodeInjection: true, deadCodeInjectionThreshold: 1, stringArray: true, stringArrayThreshold: 1 },
  'transform-keys-unicode': { transformObjectKeys: true, unicodeEscapeSequence: true, stringArray: true, stringArrayThreshold: 1, numbersToExpressions: true },
};
for (const [name, options] of Object.entries(cases)) {
  const code = JavaScriptObfuscator.obfuscate(source, Object.assign({}, base, options)).getObfuscatedCode();
  fs.writeFileSync(path.join(out, `obfuscator-${name}.js`), code + '\n');
}

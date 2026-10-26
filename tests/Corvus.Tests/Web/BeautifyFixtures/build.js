// Minifies program.js into program.min.js with terser (5.39.0): names mangled, statements joined on one line.
// Usage: node build.js <folder holding node_modules/terser>
const fs = require("fs");
const path = require("path");
const { minify } = require(path.join(process.argv[2], "node_modules", "terser"));

(async () => {
  const source = fs.readFileSync(path.join(__dirname, "program.js"), "utf8");
  const result = await minify(source, { compress: false, mangle: { toplevel: false }, format: { comments: false } });
  fs.writeFileSync(path.join(__dirname, "program.min.js"), result.code + "\n");
})();

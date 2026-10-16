namespace Corvus.Services.Web.Packages;

/// <summary>
/// Widely installed package names from the registries' public download rankings: a new name one or two edits away from one
/// of these is worth a second look. Matching a name exactly is never a finding.
/// </summary>
internal static class PopularNames
{
    public static readonly HashSet<string> Npm = new(StringComparer.OrdinalIgnoreCase)
    {
        "lodash", "react", "react-dom", "chalk", "tslib", "commander", "express", "axios", "debug", "moment", "request", "uuid", "async", "semver",
        "glob", "minimist", "yargs", "colors", "underscore", "bluebird", "fs-extra", "classnames", "prop-types", "webpack", "babel-core",
        "typescript", "core-js", "rxjs", "mkdirp", "rimraf", "inquirer", "body-parser", "cheerio", "jquery", "vue", "angular", "dotenv",
        "eslint", "prettier", "jest", "mocha", "chai", "sinon", "redux", "react-redux", "next", "nuxt", "electron", "socket.io", "ws",
        "node-fetch", "cross-env", "cross-spawn", "nodemon", "mongoose", "mysql", "mysql2", "pg", "redis", "sequelize", "knex", "passport",
        "jsonwebtoken", "bcrypt", "bcryptjs", "crypto-js", "nanoid", "dayjs", "date-fns", "ramda", "immutable", "qs", "cookie", "cors",
        "helmet", "morgan", "winston", "pino", "ora", "boxen", "figlet", "execa", "shelljs", "puppeteer", "playwright", "sharp", "jimp",
        "canvas", "esbuild", "rollup", "vite", "parcel", "gulp", "grunt", "browserify", "babel-loader", "css-loader", "style-loader",
        "sass", "node-sass", "less", "postcss", "autoprefixer", "tailwindcss", "bootstrap", "font-awesome", "d3", "three", "chart.js",
        "highlight.js", "marked", "markdown-it", "handlebars", "ejs", "pug", "mustache", "xml2js", "js-yaml", "yaml", "ini", "toml",
        "graphql", "apollo-server", "prisma", "typeorm", "zod", "joi", "ajv", "validator", "yup", "formik", "styled-components", "emotion",
        "@babel/core", "@types/node", "@types/react", "@angular/core", "@vue/cli", "eslint-plugin-react", "ts-node", "tsx", "nx", "lerna",
        "husky", "lint-staged", "concurrently", "npm-run-all", "http-server", "serve", "live-server", "open", "chokidar", "minimatch",
        "picomatch", "micromatch", "fast-glob", "globby", "string-width", "strip-ansi", "ansi-styles", "supports-color", "kleur", "picocolors",
        "event-stream", "ua-parser-js", "coa", "rc", "node-ipc", "faker", "left-pad", "is-promise", "discord.js", "web3", "ethers",
        "electron-builder", "electron-updater", "aws-sdk", "firebase", "stripe", "twilio", "nodemailer", "multer", "busboy", "form-data",
        "superagent", "got", "ky", "undici", "tough-cookie", "jsdom", "puppeteer-core", "selenium-webdriver", "socket.io-client",
    };

    public static readonly HashSet<string> PyPI = new(StringComparer.OrdinalIgnoreCase)
    {
        "requests", "urllib3", "boto3", "botocore", "setuptools", "certifi", "idna", "charset-normalizer", "typing-extensions", "python-dateutil",
        "six", "s3transfer", "pyyaml", "numpy", "packaging", "cryptography", "pip", "wheel", "jmespath", "pydantic", "attrs", "cffi",
        "pycparser", "protobuf", "rsa", "pyasn1", "google-api-core", "importlib-metadata", "zipp", "platformdirs", "pandas", "click",
        "markupsafe", "jinja2", "colorama", "filelock", "pytz", "tomli", "awscli", "virtualenv", "pyjwt", "wrapt", "decorator", "pytest",
        "pluggy", "iniconfig", "exceptiongroup", "aiohttp", "multidict", "yarl", "frozenlist", "aiosignal", "async-timeout", "grpcio",
        "googleapis-common-protos", "sqlalchemy", "greenlet", "psutil", "pillow", "scipy", "matplotlib", "requests-oauthlib", "oauthlib",
        "werkzeug", "flask", "itsdangerous", "django", "fastapi", "starlette", "uvicorn", "httpx", "httpcore", "anyio", "sniffio", "h11",
        "beautifulsoup4", "soupsieve", "lxml", "tqdm", "rich", "pygments", "docutils", "sphinx", "openpyxl", "xlrd", "pyparsing", "regex",
        "scikit-learn", "joblib", "threadpoolctl", "tensorflow", "keras", "torch", "torchvision", "transformers", "tokenizers", "huggingface-hub",
        "safetensors", "openai", "anthropic", "langchain", "tiktoken", "nltk", "spacy", "selenium", "paramiko", "pynacl", "bcrypt",
        "pymysql", "psycopg2", "psycopg2-binary", "redis", "pymongo", "celery", "kombu", "billiard", "gunicorn", "websockets", "websocket-client",
        "simplejson", "ujson", "orjson", "msgpack", "markdown", "mock", "coverage", "tox", "black", "flake8", "pylint", "mypy", "isort",
        "pre-commit", "poetry", "twine", "build", "jsonschema", "fsspec", "pyarrow", "matplotlib-inline", "ipython", "jupyter", "notebook",
        "colorlog", "loguru", "discord", "discord.py", "pycryptodome", "pycrypto", "py", "tabulate", "termcolor", "python-dotenv", "dnspython",
    };
}

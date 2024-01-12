# Phishing blocker browser extension
TypeScript, Python, Node.js, basic Chrome browser extension stuff

## File layout
The `dist` folder is where the compiled project will end up.
The `public` folder is where all of the regular Chrome browser extension files are located.
The `src` folder has the TypeScript and Python code.
`webpack` is webpack (no touchy)
`node_modules` is Node.js (no touchy)

## Compiling the TS code
`npm run build`
npm by default looks at `package.json` to know what to run
`package.json` is configured to run `webpack --config webpack.config.js`
`webpack.config.js` is configured to use `ts-loader` to compile the TS files to JS in the `dist` folder
`webpack.config.js` also uses the `copy-webpack-plugin` to copy everything from the `public` folder to the `dist` folder as-is
`ts-loader` does the equivalent of calling `tsc` which then reads the `tsconfig.json` file to know that we want to compile the `.ts` files in the `src` folder to the `dist` folder
so basically:
`npm run build` --> reads `package.json` --> calls `webpack --config webpack.config.js` --> uses `ts-loader` --> read `tsconfig.json` --> compile `.ts` to `.js`

## Adding as Chrome extension
The `dist` folder contains the extension code


## Node Package Manager commands
`npm init -y`
`npm install --save-dev webpack webpack-cli`
`npm install --save-dev copy-webpack-plugin`
`npm install --save-dev typescript ts-loader`
`npm install --save-dev @types/chrome`
`npm install --save-dev @types/node`

## Testing Lambda
`curl -X POST https://mwo0rju1el.execute-api.us-east-1.amazonaws.com/pyantiphish/url_analyzer -d '{"url": "https://www.google.com"}'`
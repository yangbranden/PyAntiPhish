import path from 'path';
import CopyPlugin from 'copy-webpack-plugin';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url))

export default {
	mode: "production",
	entry: {
		background: path.resolve(__dirname, "./src/background.ts"),	
	},
	output: {
		path: path.resolve(__dirname, "dist"),
		filename: "[name].js",
	},
	resolve: {
		extensions: [".ts", ".js"],
	},
	module: {
		rules: [
			{
				test: /\.ts$/,
				loader: "ts-loader",
				exclude: /node_modules/,
			},
		],
	},
	plugins: [
		new CopyPlugin({
			patterns: [{from: ".", to: ".", context: "public"}]
		}),
	],
};

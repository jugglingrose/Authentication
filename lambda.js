'use strict'

const awsServerlessExpress = require('aws-serverless-express');
const awsServerlessExpressMiddleware = require('aws-serverless-express/middleware');

const app = require('./app');

app.use(awsServerlessExpressMiddleware.eventContext());

console.log("Initializing awsServerlessExpress...");
const server = awsServerlessExpress.createServer(app);
exports.handler = (event, context) => awsServerlessExpress.proxy(server, event, context);

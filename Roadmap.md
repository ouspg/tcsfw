# Tcsfw roadmap

The following provides a rough overview of how we see the tcsfw framework developing towards useful security assessment toolkit.

## Core features

The following features are planned in the core functionality of the framework: security statements, claims, tool output processing, verdict assignment.

 * Add and update features required when new security statements are created
 * Improve performace with larger sets of tool data to process
 * Test integration with production-grade SQL databasese

## Web API 

The following features are planned for the _Web API_ of the framework

 * User authentication beyond HTTP basic authentication
 * More robust tool result upload, including deduplication
 * Pull assessment results to be used in other systems
 * Formal documentaiton using _OpenAPI_

## Deployment

The framework should be deployed for production use. This is envisioned using _Open container_ format.

 * Build official container image of the framework

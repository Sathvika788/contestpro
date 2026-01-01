// create-tables-secure.js
const { DynamoDBClient, CreateTableCommand } = require("@aws-sdk/client-dynamodb");

// Load environment variables
require('dotenv').config({ path: '.env' });

// Validate credentials
function validateCredentials() {
    const required = ['AWS_REGION', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'];
    const missing = required.filter(key => !process.env[key]);
    
    if (missing.length > 0) {
        console.error(`❌ Missing environment variables: ${missing.join(', ')}`);
        console.log('Please check your .env file');
        return false;
    }
    
    // Mask the access key for security
    const maskedKey = process.env.AWS_ACCESS_KEY_ID 
        ? process.env.AWS_ACCESS_KEY_ID.substring(0, 4) + '...' 
        : 'not set';
    
    console.log(`✅ AWS Region: ${process.env.AWS_REGION}`);
    console.log(`✅ Access Key: ${maskedKey}`);
    console.log(`✅ Secret Key: ${process.env.AWS_SECRET_ACCESS_KEY ? '*** set ***' : 'not set'}`);
    
    return true;
}

// Create table helper
async function createTable(tableName, params) {
    const client = new DynamoDBClient({
        region: process.env.AWS_REGION,
        credentials: {
            accessKeyId: process.env.AWS_ACCESS_KEY_ID,
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
        }
    });

    try {
        console.log(`\n📦 Creating ${tableName} table...`);
        const command = new CreateTableCommand(params);
        const response = await client.send(command);
        console.log(`✅ ${tableName} table created successfully!`);
        console.log(`   Table ARN: ${response.TableDescription.TableArn}`);
        console.log(`   Status: ${response.TableDescription.TableStatus}`);
        return true;
    } catch (error) {
        if (error.name === 'ResourceInUseException') {
            console.log(`✅ ${tableName} table already exists`);
            return true;
        } else if (error.name === 'UnrecognizedClientException') {
            console.error(`❌ Invalid AWS credentials for ${tableName}`);
            console.error('   Please check your AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY');
            return false;
        } else if (error.name === 'AccessDeniedException') {
            console.error(`❌ Permission denied for ${tableName}`);
            console.error('   Your IAM user needs DynamoDB create permissions');
            return false;
        } else {
            console.error(`❌ Error creating ${tableName}:`, error.message);
            return false;
        }
    }
}

// Main function
async function main() {
    console.log("🔐 AWS DynamoDB Table Setup");
    console.log("=============================");
    
    // Validate credentials first
    if (!validateCredentials()) {
        process.exit(1);
    }
    
    // Create StudentSubmissions table
    const submissionsSuccess = await createTable("StudentSubmissions", {
        TableName: "StudentSubmissions",
        AttributeDefinitions: [
            { AttributeName: "submission_id", AttributeType: "S" },
            { AttributeName: "student_email", AttributeType: "S" },
            { AttributeName: "contest_id", AttributeType: "S" }
        ],
        KeySchema: [
            { AttributeName: "submission_id", KeyType: "HASH" }
        ],
        BillingMode: "PAY_PER_REQUEST",
        GlobalSecondaryIndexes: [
            {
                IndexName: "StudentSubmissionsIndex",
                KeySchema: [{ AttributeName: "student_email", KeyType: "HASH" }],
                Projection: { ProjectionType: "ALL" }
            },
            {
                IndexName: "ContestSubmissionsIndex",
                KeySchema: [{ AttributeName: "contest_id", KeyType: "HASH" }],
                Projection: { ProjectionType: "ALL" }
            }
        ]
    });
    
    // Create StudentResults table
    const resultsSuccess = await createTable("StudentResults", {
        TableName: "StudentResults",
        AttributeDefinitions: [
            { AttributeName: "result_id", AttributeType: "S" },
            { AttributeName: "student_email", AttributeType: "S" },
            { AttributeName: "contest_id", AttributeType: "S" }
        ],
        KeySchema: [
            { AttributeName: "result_id", KeyType: "HASH" }
        ],
        BillingMode: "PAY_PER_REQUEST",
        GlobalSecondaryIndexes: [
            {
                IndexName: "StudentResultsIndex",
                KeySchema: [{ AttributeName: "student_email", KeyType: "HASH" }],
                Projection: { ProjectionType: "ALL" }
            },
            {
                IndexName: "ContestResultsIndex",
                KeySchema: [{ AttributeName: "contest_id", KeyType: "HASH" }],
                Projection: { ProjectionType: "ALL" }
            }
        ]
    });
    
    // Summary
    console.log("\n📊 Setup Summary:");
    console.log("=================");
    console.log(`StudentSubmissions: ${submissionsSuccess ? '✅ Ready' : '❌ Failed'}`);
    console.log(`StudentResults: ${resultsSuccess ? '✅ Ready' : '❌ Failed'}`);
    
    if (submissionsSuccess && resultsSuccess) {
        console.log("\n🎉 All tables are ready! You can now run:");
        console.log("   node server.js");
    } else {
        console.log("\n⚠️  Some tables failed to create. Check errors above.");
    }
}

// Run with error handling
main().catch(error => {
    console.error("Fatal error:", error.message);
    process.exit(1);
});
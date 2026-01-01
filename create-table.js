const { DynamoDBClient, CreateTableCommand, DescribeTableCommand } = require("@aws-sdk/client-dynamodb");
require('dotenv').config();

const client = new DynamoDBClient({
    region: process.env.AWS_REGION || "ap-south-1",
    credentials: {
        accessKeyId: (process.env.AWS_ACCESS_KEY_ID || "").trim(),
        secretAccessKey: (process.env.AWS_SECRET_ACCESS_KEY || "").trim()
    }
});

async function createContestProgressionRulesTable() {
    const tableName = "ContestProgressionRules";
    
    try {
        console.log(`Checking if table ${tableName} exists...`);
        
        // First, check if table exists
        try {
            await client.send(new DescribeTableCommand({ TableName: tableName }));
            console.log(`✓ Table ${tableName} already exists`);
            return;
        } catch (err) {
            if (err.name !== 'ResourceNotFoundException') {
                throw err;
            }
        }
        
        console.log(`Creating table ${tableName}...`);
        
        const params = {
            TableName: tableName,
            KeySchema: [
                { AttributeName: "rule_id", KeyType: "HASH" }
            ],
            AttributeDefinitions: [
                { AttributeName: "rule_id", AttributeType: "S" },
                { AttributeName: "normal_contest_id", AttributeType: "S" },
                { AttributeName: "debug_contest_id", AttributeType: "S" },
                { AttributeName: "created_by", AttributeType: "S" }
            ],
            GlobalSecondaryIndexes: [
                {
                    IndexName: "NormalContestIndex",
                    KeySchema: [
                        { AttributeName: "normal_contest_id", KeyType: "HASH" }
                    ],
                    Projection: { ProjectionType: "ALL" },
                    ProvisionedThroughput: {
                        ReadCapacityUnits: 5,
                        WriteCapacityUnits: 5
                    }
                },
                {
                    IndexName: "DebugContestIndex",
                    KeySchema: [
                        { AttributeName: "debug_contest_id", KeyType: "HASH" }
                    ],
                    Projection: { ProjectionType: "ALL" },
                    ProvisionedThroughput: {
                        ReadCapacityUnits: 5,
                        WriteCapacityUnits: 5
                    }
                },
                {
                    IndexName: "ModeratorRulesIndex",
                    KeySchema: [
                        { AttributeName: "created_by", KeyType: "HASH" }
                    ],
                    Projection: { ProjectionType: "ALL" },
                    ProvisionedThroughput: {
                        ReadCapacityUnits: 5,
                        WriteCapacityUnits: 5
                    }
                }
            ],
            ProvisionedThroughput: {
                ReadCapacityUnits: 10,
                WriteCapacityUnits: 10
            }
        };
        
        await client.send(new CreateTableCommand(params));
        console.log(`✓ Table ${tableName} created successfully!`);
        
        // Wait for table to become active
        console.log("Waiting for table to become active...");
        await waitForTableActive(tableName);
        console.log("✅ Table is now ACTIVE and ready to use!");
        
    } catch (err) {
        console.error("Error creating table:", err);
        console.error("Error details:", JSON.stringify(err, null, 2));
    }
}

async function waitForTableActive(tableName, maxRetries = 30, delay = 1000) {
    for (let i = 0; i < maxRetries; i++) {
        try {
            const { Table } = await client.send(new DescribeTableCommand({ TableName: tableName }));
            
            if (Table.TableStatus === 'ACTIVE') {
                return true;
            }
            
            console.log(`Table status: ${Table.TableStatus}, waiting... (${i + 1}/${maxRetries})`);
            await new Promise(resolve => setTimeout(resolve, delay));
            
        } catch (err) {
            console.error("Error checking table status:", err.message);
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
    throw new Error(`Table ${tableName} did not become active within ${maxRetries * delay / 1000} seconds`);
}

// Run the function
createContestProgressionRulesTable();
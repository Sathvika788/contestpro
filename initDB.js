require('dotenv').config();
const { DynamoDBClient, CreateTableCommand } = require("@aws-sdk/client-dynamodb");

const client = new DynamoDBClient({
    region: process.env.AWS_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    }
});

const tables = [
    {
        TableName: "Moderators",
        KeySchema: [{ AttributeName: "email", KeyType: "HASH" }],
        AttributeDefinitions: [{ AttributeName: "email", AttributeType: "S" }]
    },
    {
        TableName: "Colleges",
        KeySchema: [{ AttributeName: "college_id", KeyType: "HASH" }],
        AttributeDefinitions: [{ AttributeName: "college_id", AttributeType: "S" }]
    },
    {
        TableName: "Students",
        KeySchema: [{ AttributeName: "email", KeyType: "HASH" }],
        AttributeDefinitions: [{ AttributeName: "email", AttributeType: "S" }]
    },
    {
        TableName: "Contests",
        KeySchema: [{ AttributeName: "contest_id", KeyType: "HASH" }],
        AttributeDefinitions: [{ AttributeName: "contest_id", AttributeType: "S" }]
    },
    {
        TableName: "Scores",
        KeySchema: [
            { AttributeName: "contest_id", KeyType: "HASH" }, // Which contest
            { AttributeName: "student_email", KeyType: "RANGE" } // Which student
        ],
        AttributeDefinitions: [
            { AttributeName: "contest_id", AttributeType: "S" },
            { AttributeName: "student_email", AttributeType: "S" }
        ]
    }
];

async function createTables() {
    for (const table of tables) {
        try {
            const command = new CreateTableCommand({
                ...table,
                ProvisionedThroughput: { ReadCapacityUnits: 5, WriteCapacityUnits: 5 }
            });
            await client.send(command);
            console.log(`✅ Table "${table.TableName}" created successfully.`);
        } catch (err) {
            if (err.name === "ResourceInUseException") {
                console.log(`ℹ️ Table "${table.TableName}" already exists.`);
            } else {
                console.error(`❌ Error creating ${table.TableName}:`, err);
            }
        }
    }
}

createTables();
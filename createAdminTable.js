require('dotenv').config();
const { DynamoDBClient, CreateTableCommand } = require("@aws-sdk/client-dynamodb");

const client = new DynamoDBClient({
    region: process.env.AWS_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    }
});

async function createAdminTable() {
    const params = {
        TableName: "AdminTable",
        KeySchema: [{ AttributeName: "email", KeyType: "HASH" }],
        AttributeDefinitions: [{ AttributeName: "email", AttributeType: "S" }],
        ProvisionedThroughput: { ReadCapacityUnits: 5, WriteCapacityUnits: 5 }
    };

    try {
        await client.send(new CreateTableCommand(params));
        console.log('✅ Table "AdminTable" created successfully.');
    } catch (err) {
        if (err.name === "ResourceInUseException") {
            console.log('ℹ️ Table "AdminTable" already exists.');
        } else {
            console.error('❌ Error:', err);
        }
    }
}

createAdminTable();
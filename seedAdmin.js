require('dotenv').config();
const { DynamoDBClient, PutItemCommand } = require("@aws-sdk/client-dynamodb");
const { marshall } = require("@aws-sdk/util-dynamodb");
const bcrypt = require('bcryptjs');

const client = new DynamoDBClient({ region: process.env.AWS_REGION });

async function seed() {
    const email = "admin@contest.com"; 
    const password = "AdminPassword123"; // Use this to log in
    const hashedPassword = await bcrypt.hash(password, 10);

    const params = {
        TableName: "AdminTable",
        Item: marshall({
            email: email,
            password: hashedPassword,
            name: "Master Admin",
            role: "admin"
        })
    };

    try {
        await client.send(new PutItemCommand(params));
        console.log(`✅ Admin Created! \nEmail: ${email} \nPassword: ${password}`);
    } catch (err) {
        console.error("❌ Error seeding admin:", err);
    }
}
seed();
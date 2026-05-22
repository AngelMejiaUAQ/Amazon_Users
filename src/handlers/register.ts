import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda"
import { badRequest, ok } from "../lib/response"
import { PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb"
import bcryp from "bcryptjs"
import { v4 as uuidv4 } from "uuid"
import { dynamo } from "../lib/dynamodb"
import { User } from "../types/user"
import { withCors } from "../common/cors";

const USERS_TABLE = process.env.USERS_TABLE!;

export async function handler(event: APIGatewayProxyEvent) : Promise <APIGatewayProxyResult> {
    try {
        const body = JSON.parse(event.body || "{}");
        const { email, password, username, role = "buyer" } = body;

        if (!username || !email || !password) {
            return badRequest("El email, password y nombre de usuario son requeridos")
        }

        const existing = await dynamo.send(
            new QueryCommand({
                TableName: USERS_TABLE,
                IndexName: "EmailIndex",
                KeyConditionExpression: "email = :email",
                ExpressionAttributeValues: {
                    ":email": email
                }
            })
        );

        if (existing.Items && existing.Items.length > 0) {
            return badRequest("El email ya está registrado")
        }

        const hashedPassword = await bcryp.hash(password, 10);
        const now = new Date().toISOString();

        const user: User = {
            userId: uuidv4(),
            email,
            password: hashedPassword,
            username,
            role,
            createdAt: now,
            updatedAt: now
        };

        await dynamo.send(
            new PutCommand({
                TableName: USERS_TABLE,
                Item: {
                    ...user
                }
            })
        );

        const { password: _, ...userPublic } = user

        return ok({userPublic})

    } catch (error) {
        console.error("Error al registrar usuario:", error)
        return {
            statusCode: 500,
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                success: false,
                message: "Error al registrar usuario"
            })
        }
    }
}

export const register = withCors(handler);
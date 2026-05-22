import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda"
import { badRequest, ok, unauthorized, internalError, notFound } from "../lib/response"
import { GetCommand, PutCommand , QueryCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb"
import bcrypt from "bcryptjs"
import { generateAccessToken, generateRefreshToken } from "../lib/jwt"
import { dynamo } from "../lib/dynamodb"
import { withCors } from "../common/cors";


const USERS_TABLE = process.env.USERS_TABLE!;

export async function handler(event: APIGatewayProxyEvent) : Promise <APIGatewayProxyResult> {
    try {
        const userId = event.pathParameters?.id;
        if (!userId) {
            return notFound("Usuario no encontrado")
        }

        const callerId = event.requestContext.authorizer?.userId;

        if (callerId !== userId) {
            return badRequest("No puedes actualizar un usuario que no es tuyo")
        }

        const body = JSON.parse(event.body ?? "{}");
        const { username } = body;

        if (!username) {
            return badRequest("El nombre es requerido")
        }

        const existing = await dynamo.send(
            new GetCommand({
                TableName: USERS_TABLE!,
                Key: {
                    userId
                }
            })
        );

        if (!existing.Item) {
            return notFound("Usuario no encontrado en base de datos")
        }

        const now = new Date().toISOString();
        await dynamo.send(
            new UpdateCommand({
                TableName: USERS_TABLE!,
                Key: {
                    userId
                },
                UpdateExpression: "set #username = :username, updatedAt = :updatedAt",
                ExpressionAttributeNames: {
                    "#username": "username"
                },
                ExpressionAttributeValues: {
                    ":username": username,
                    ":updatedAt": now
                }
            })
        );

        return ok({ message: "Usuario actualizado correctamente" })
    } catch (error) {
        console.error("Error en updateUser", error);
        return internalError();
    }
}   

export const updateUser = withCors(handler);
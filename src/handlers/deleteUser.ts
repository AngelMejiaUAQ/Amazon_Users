import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda"
import { badRequest, ok, internalError, notFound } from "../lib/response"
import { DeleteCommand, GetCommand, } from "@aws-sdk/lib-dynamodb"
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
            return badRequest("No puedes eliminar un usuario que no es tuyo")
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

        await dynamo.send(
            new DeleteCommand({
                TableName: USERS_TABLE!,
                Key: {
                    userId
                }
            })
        );

        return ok({ message: "Usuario eliminado correctamente" })
    } catch (error) {
        console.error("Error en deleteUser", error);
        return internalError();
    }
}

export const deleteUser = withCors(handler);
import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { badRequest, ok, unauthorized, internalError } from "../lib/response";
import { GetCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";
import { dynamo } from "../lib/dynamodb";
import { verifyRefreshToken, generateAccessToken } from "../lib/jwt";
import { withCors } from "../common/cors";

const USERS_TABLE = process.env.USERS_TABLE!;
const REFRESH_TOKENS_TABLE = process.env.REFRESH_TOKENS_TABLE!;

export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const body = JSON.parse(event.body ?? "{}");
    const { refreshToken } = body as { refreshToken?: string };

    if (!refreshToken || typeof refreshToken !== "string") {
      return badRequest("El refreshToken es requerido");
    }

    const payload = verifyRefreshToken(refreshToken);

    const storedToken = await dynamo.send(
      new GetCommand({
        TableName: REFRESH_TOKENS_TABLE,
        Key: { token: refreshToken },
      })
    );

    if (!storedToken.Item || storedToken.Item.userId !== payload.userId) {
      return unauthorized("La sesión ha expirado, inicia sesión nuevamente");
    }

    const user = await dynamo.send(
      new QueryCommand({
        TableName: USERS_TABLE,
        IndexName: "EmailIndex",
        KeyConditionExpression: "email = :email",
        ExpressionAttributeValues: {
          ":email": payload.email,
        },
      })
    );

    const account = user.Items?.[0];

    if (!account) {
      return unauthorized("La sesión ha expirado, inicia sesión nuevamente");
    }

    const accessToken = generateAccessToken({
      userId: account.userId,
      email: account.email,
      role: account.role,
    });

    return ok({ accessToken });
  } catch (error) {
    console.error("Error en refresh", error);
    return internalError();
  }
}

export const refresh = withCors(handler);
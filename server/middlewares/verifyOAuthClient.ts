import type { NextFunction, Request, Response } from "express";
import { authenticateClient } from "@server/lib/oauth/clientAuth";
import HttpCode from "@server/types/HttpCode";
import logger from "@server/logger";

export type JsonErrorType = { error: string; error_description?: string };

export async function verifyOAuthClient(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<Response | void> {
    try {
        req.oauthClient = await authenticateClient(req);
        return next();
    } catch (error) {
        logger.warn(error);
    }

    return sendJsonHttpError(
        res,
        HttpCode.UNAUTHORIZED,
        {
            error: "invalid_client",
            error_description: "Invalid client credentials"
        },
        !!req.headers.authorization
    );
}

export function sendJsonHttpError(
    res: Response,
    status: HttpCode,
    jsonError: JsonErrorType,
    authHeader: boolean = false
): Response {
    if (authHeader) {
        // The header MUST have another parameter, recommended is "realm"
        if (!(jsonError instanceof JsonHttpError)) {
            if (Object.keys(jsonError).length === 0)
                (jsonError as any)["realm"] = "oauth";
        }
        res.setHeader(
            "WWW-Authenticate",
            `Basic ${Object.entries(jsonError)
                .map((e) => e.join('="'))
                .join('", ')}"`
        );
    }

    return res.status(status).json(jsonError);
}

export class JsonHttpError extends Error {
    constructor(
        public code: HttpCode,
        public jsonError: JsonErrorType
    ) {
        super(jsonError.error_description || "OAuth Validation Error");
        this.name = "OAuthValidationError";
    }
}

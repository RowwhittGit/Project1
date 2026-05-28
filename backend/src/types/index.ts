export type Error = {
    name?: string,
    errors?: any,
    statusCode: number,
    message: string,
    errorCode: number
}

export type RETURN_ERROR = {
    message: string,
    errorCode: number
}

export type SSO_GOOGLE_IDENTITY_SERVICES_TOKEN_DECODED = {
    email: string;
    name: string;
    picture: string;
}

export interface User {
    userId: string;
    email: string;
    password: string;
    username: string;
    role: "buyer" | "seller";
    createdAt: string;
    updatedAt: string;
}
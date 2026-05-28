import mongoose, { Schema, Document } from 'mongoose';

export interface RefreshToken extends Document {
    token: string;
    user_id: string | any;
    expiresAt: Date;
}

const refreshTokenSchema: Schema<RefreshToken> = new Schema<RefreshToken>({
    token: { type: String, required: true, unique: true },
    user_id: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    expiresAt: { type: Date, required: true }
}, { versionKey: false });

refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export default mongoose.model<RefreshToken>('RefreshToken', refreshTokenSchema);

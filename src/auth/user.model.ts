import * as mongoose from 'mongoose';
import * as bcrypt from 'bcrypt';
import { Role } from '../core/enums/role.enum';

export const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        unique: true,
        required: true
    },
    name: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    emailVerified: {
        type: Boolean,
        default: false
    },
    roles: {
        type: [],
        default: [Role.User]
    },
    refreshToken: {
        type: String
    }
}, { timestamps: true });

export const TokenVerifyEmailSchema = new mongoose.Schema({
    userId: {
       type: mongoose.Schema.Types.ObjectId, ref: 'users' 
    },
    tokenVerifyEmail: {
        type: String,
    }
}, { timestamps: true });

// NOTE: Arrow functions are not used here as we do not want to use lexical scope for 'this'
UserSchema.pre('save', function (next) {
    let user = this as any;
    // Make sure not to rehash the password if it is already hashed
    if (!user.isModified('password')) return next();
    // Generate a salt and use it to hash the user's password
    bcrypt.genSalt(10, (err, salt) => {
        if (err) return next(err);
        bcrypt.hash(user.password, salt, (err, hash) => {
            if (err) return next(err);
            user.password = hash;
            next();
        });
    });
});

UserSchema.methods.checkPassword = function (attempt, callback) {
    let user = this;
    bcrypt.compare(attempt, user.password, (err, isMatch) => {
        if (err) return callback(err);
        callback(null, isMatch);
    });
};

UserSchema.methods.compareRefreshTokens = async function (refreshToken:string): Promise<boolean>{
    return bcrypt.compareAsync(refreshToken, this.refreshToken)
}

export interface User extends mongoose.Document {
    _id: string;
    email: string;
    name: string;
    password: string;
    emailVerified: Boolean;
    roles: Role[];
    refreshToken: string
}


export interface TokenVerifyEmail extends mongoose.Document {
    userId: string,
    tokenVerifyEmail: string;
}
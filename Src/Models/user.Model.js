import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
const UserSchema = new mongoose.Schema({
    username:{
        type:String,
        required:true,
        unique:true,
        lowercase:true,
        trim:true,
        index:true
    },
     email:{
        type:String,
        required:true,
        unique:true,
        lowercase:true,
        trim:true,
       
    },
    fullname:{
        type:String,
        required:true,
        trim:true,
        index:true
    },
    avatar:{
        type:String,
        required:true,
    },
    coverImage:{
        type:String,
    },
    watchHistory:[{
        type:mongoose.Schema.Types.ObjectId,
        ref:"VideoModel"
    }],
    watachLater:[{
        type:mongoose.Schema.Types.ObjectId,
        ref:"VideoModel"
    }],
    password:{
        type:String,
        required:[true,"Password is required"],  

    },
    refreshToken:{
        type:String,
    },
},{timestamps:true})

//Always use function keyword instead of arrow function to access "this" keyword
UserSchema.pre("save",async function(next){
    if(!this.isModified("password")) return next()//If password is not modified, skip hashing and move to the next middleware
    const salt = await bcrypt.genSalt(10)
    this.password = await bcrypt.hash(this.password,salt)
    next()
})


//Method to generate JWT token for authentication
UserSchema.methods.comparePassword = async function(candidatePassword){
    return await bcrypt.compare(candidatePassword, this.password)
}

UserSchema.methods.generateAccessToken = function(){
    //Sign a JWT token with the user's ID as the payload, using the secret key and expiration time from environment variables
    return jwt.sign({_id:this._id,
        username:this.username,
        email:this.email,
    },process.env.ACCESS_TOKEN_SECRET,{expiresIn:process.env.ACCESS_TOKEN_EXPIRES_IN})
}

UserSchema.methods.generateRefreshToken = function(){
    return jwt.sign({id:this._id},process.env.REFRESH_TOKEN_SECRET,{expiresIn:process.env.REFRESH_TOKEN_EXPIRES_IN})
}

export const User = mongoose.model("User", UserSchema)
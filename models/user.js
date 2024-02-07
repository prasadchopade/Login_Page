import mongoose from "mongoose";

const userSchema = mongoose.Schema({
    username:{
        type:String
    },
    password:{
        type:String
    }
},{collection:'Users'});

const Users = mongoose.model("Users",userSchema);

export default Users;
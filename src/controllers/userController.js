const userModel = require("../models/userModel")
const bcrypt = require("bcrypt")
const  { isValid,isValidBody, validString, validMobileNum, validEmail, validPwd, isValidObjectId, isValidImage,isValidPincode} = require('../utils/validation')
const AWS= require("aws-sdk")
const jwt = require("jsonwebtoken")
const {uploadFile} = require("../utils/awss3")



  //----------------------------------------------------------POST /register----------------------------------------------------------------

const createUser= async function(req, res) {
    try{

    let files= req.files  
    let data= req.body

    //check body of data
    if(isValidBody(data)) return res.status(400).send({status: false, message: "Enter user details"})

    //check key & value of Data is Present or not
    if(!data.fname) return res.status(400).send({status: false, message: "FirstName is required"})
    if(!data.lname) return res.status(400).send({status: false, message: "LastName is required"})
    if(!data.email) return res.status(400).send({status: false, message: "Email ID is required"})
    if(!data.phone) return res.status(400).send({status: false, message: "Mobile number is required"})
    if(!data.password) return res.status(400).send({status: false, message: "Password is required"})

    //checking for address
    if(!data.address) return res.status(400).send({status: false, message: "Address is required"})

    //convert json to parse 
    data.address = JSON.parse(data.address)

    //validate shipping address
    //if(isValid(data.address)) return res.status(400).send({status: false, message: "Address should be in object and must contain shipping and billing address"})
    if(!data.address.shipping) return res.status(400).send({status: false, message: "shipping address should be with street, city and pincode"})

    //check in shipping street,city and pincode is present or not
    if(!data.address.shipping.street) return res.status(400).send({status: false, message: "shipping street is required"})
    if(!data.address.shipping.city) return res.status(400).send({status: false, message: "shipping city is required"})
    if(!data.address.shipping.pincode) return res.status(400).send({status: false, message: "shipping pincode is required"})

    //validate billing address
    if(!data.address.billing) return res.status(400).send({status: false, message: "billing address should be with street, city and pincode"})

    //check in billing address street, city and pincode is present or not
    if(!data.address.billing.street) return res.status(400).send({status: false, message: "billing street is required"})
    if(!data.address.billing.city) return res.status(400).send({status: false, message: "billing city is required"})
    if(!data.address.billing.pincode) return res.status(400).send({status: false, message: "billing pincode is required"})


    
    //validate firstname and lastname
    if(validString(data.fname) ||validString(data.lname) ) return res.status(400).send({status: false, message: "FirstName and LastName should be characters and should not contains any numbers"})

    //validate email
    if(validEmail(data.email)) return res.status(400).send({status: false, message: "Enter a valid email-id"})

    //validate mobile number
    if(validMobileNum(data.phone)) return res.status(400).send({status: false, message: "Enter a 10-digit Indian phone number exluding (+91)"})

    //validate password
    if(validPwd(data.password)) return res.status(400).send({status: false, message: "Password should be 8-15 characters long and must contain one of 0-9,A-Z,a-z and special characters"})

    //create password to hash password
    const salt = await bcrypt.genSalt(10)
    data.password = await bcrypt.hash(data.password, salt)

    //check email and password is already exist or not
    let checkUniqueValues = await userModel.findOne({$or: [{phone: data.phone}, {email: data.email}]})
    if(checkUniqueValues) return res.status(400).send({status: false, message: "E-Mail or phone number already exist"})

    //create a file
    if(files.length == 0) return res.status(400).send({status: false, message: "Profile Image is required"})
    if(!isValidImage(files && files.length>0)){
        let uploadedFileURL= await uploadFile( files[0] )
        data.profileImage = uploadedFileURL
     }else{
        return res.status(400).send({status: false, message: "Image is not a valid format"})
    }
    
    // here we can start user creation
    let userData= await userModel.create(data)
    res.status(201).send({status: true, message: "User created successfully", data: userData})
    }catch(err){
        res.status(500).send({status: false, Error: err.message})
    }
}

//---------------------------------------------------------------POST /login-------------------------------------------------------------------

const loginUser = async (req, res) => {
    try{
        let data = req.body;
        const {email, password} = data

        //check data is present or not
        if(Object.keys(data).length == 0) return res.status(400).send({status: false, message: "Email and Password is required for login"})

        //check email or password is present in body or not
        if(!data.email) return res.status(400).send({status: false, message: "Email field is empty"})
        if(!data.password) return res.status(400).send({status: false, message: "Password field is empty"})

        //validate email
        if(validEmail(data.email)) return res.status(400).send({status: false, message: "Enter a valid email-id"})

        //validate password
        if(validPwd(data.password)) return res.status(400).send({status: false, message: "Enter a valid password"})

        //check email is corrrect or not
        let getEmailData = await userModel.findOne({email})
        if(!getEmailData) return res.status(400).send({status: false, message: "Email is incorrect"})

        //check password is correct or not
        let passwordData = await bcrypt.compare(password, getEmailData.password)
        if(!passwordData) return res.status(400).send({status: false, message: "Password is incorrect"})

        //generate token
        let token = jwt.sign({ userId: getEmailData._id }, "Uranium Project-5", {expiresIn: '1d'});

        //assign the userdId in a variable
        let userId = getEmailData._id

        //set the headers
        //res.status(200).setHeader("x-api-key", token);

        res.status(200).send({status: true, message: "User login successfull", data: {userId: userId, token: token}})
        
    }catch(err){
        res.status(500).send({status: false, Error: err.message})
    }
}

//--------------------------------------------GET /user/:userId/profile -----------------------------------------------------------------

const getProfile = async function (req, res) {
    try {
        let userId = req.params.userId

        if(!userId) return res.status(400).send({status: false , message: "userId must be required"})

        //validate userId        
        if(!isValidObjectId(userId)) return res.status(400).send({status: false, message: "Invalid userId"})

        //get all the details 
        let userProfile = await userModel.findById({_id: userId})
        if(!userProfile)
        return res.status(400).send({status: false, message: "User doesn't exist"})
        else
        return res.status(200).send({status: true, message: "User profile details", data: userProfile})
        

    }catch(err){
        res.status(500).send({status: false, Error: err.message})
    }
}

//-------------------------------------------------------/user/:userId/profile----------------------------------------------------------

const updateUserProfile = async(req, res) => {
    try {
        let files = req.files
        let data = req.body
        let userId = req.params.userId

        //validate userId
        if (!isValidObjectId(userId)) return  res.status(400).send({ status: false, message: `${userId} is not a valid user id` })

        //check data is present or not
        if (isValidBody(data)) return res.status(400).send({status: false,message: "Invalid request parameters. Please provide user's details to update." })

        //check userId is exist or not
        const findUserProfile = await userModel.findOne({ _id: userId })
        if (!findUserProfile)  return res.status(400).send({status: false,message: `User doesn't exists by ${userId}`})
       
         //validate firstname
         if (data.fname) {
             if (validString(data.fname)) 
             return res.status(400).send({ status: false, message: "FirstName should be characters and should not contains any numbers" })
             
         }//else{
        //     if(!isValid(data.fname)) return res.status(400).send({status: false, message: "firstname is required to update the name"})
        // }
         
        //validate lastname
         if (data.lname) {
             if (validString(data.lname)) 
             return res.status(400).send({ status: false, message: "LastName should be characters and should not contains any numbers" }) 
         }//else{
        //     if(!isValid(data.lname)) return res.status(400).send({status: false, message: "lastname is required to update the name"})
        // }

         //validate email
         if (data.email) {
             if (validEmail(data.email)) 
                 return res.status(400).send({ status: false, message: "Invalid request parameter, please provide valid email" })
        //check email is already exist            
        let isEmailAlredyPresent = await userModel.findOne({ email: data.email })
        if (isEmailAlredyPresent) 
            return res.status(400).send({ status: false, message: `Unable to update email. ${data.email} is already registered.` });
        }//else{
           // if(!isValid(data.email)) return res.status(400).send({status: false, message: "emailId is required to update the email"})
        //}

        //validate phone
         if (data.phone) {
             if (validMobileNum(data.phone)) 
                 return res.status(400).send({ status: false, message: "Invalid request parameter, please provide valid and 10-digit indian Phone number exluding(+91)." })
             //check phone is already exist    
             let isPhoneAlredyPresent = await userModel.findOne({ phone: data.phone })
             if (isPhoneAlredyPresent) 
                 return res.status(400).send({ status: false, message: `Unable to update phone. ${data.phone} is already registered.` });
             }//else{
                //if(!isValid(data.phone)) return res.status(400).send({status: false, message: "phone number is required to update the phone number"})
            //}

         //validate password and setting range of password.
             if(data.password){
            if(validPwd(data.password))
            return res.status(400).send({ status: false, message: 'Password should be 8-15 characters long and must contain one of 0-9,A-Z,a-z and special characters' })
            data.password = await bcrypt.hash(data.password, 10)
             }//else{
                //if(!isValid(data.password)) return res.status(400).send({status: false, message: "password is required to update the password"})
            //}
        
        //create file
        if(files && files.length>0){
                    var uploadedFileURL= await uploadFile( files[0] )
                    data.profileImage = uploadedFileURL
                }//else{
                  //  res.status(400).send({status: false, message: "Profile Image is required to update" })
                //}

        // check address        
            if(data.address){
            //convert json to parse 
            data.address = JSON.parse(data.address)
        
            //validate shipping address
           if(isValid(data.address.shipping) && isValidBody(data.address.shipping)) return res.status(400).send({status: false, message: "shipping address should be with street, city and pincode"})
        
            //check in shipping street,city and pincode is present or not
            if(!data.address.shipping.street) return res.status(400).send({status: false, message: "shipping street is required"})
            if(!data.address.shipping.city) return res.status(400).send({status: false, message: "shipping city is required"})
            if(!data.address.shipping.pincode) return res.status(400).send({status: false, message: "shipping pincode is required"})
        
            //validate billing address
            if(isValid(data.address.billing) && isValidBody(data.address.billing)) return res.status(400).send({status: false, message: "billing address should be with street, city and pincode"})
        
            //check in billing address street, city and pincode is present or not
            if(!data.address.billing.street) return res.status(400).send({status: false, message: "billing street is required"})
            if(!data.address.billing.city) return res.status(400).send({status: false, message: "billing city is required"})
            if(!data.address.billing.pincode) return res.status(400).send({status: false, message: "billing pincode is required"})
            }else{
                if(!isValid(data.address)) return res.status(400).send({status: false, message: "address is required to update the address"})
            }
           
        //here we can update
        let changeProfileDetails = await userModel.findOneAndUpdate({ _id: userId }, data, { new: true })
        return res.status(200).send({ status: true,message: "updated successfully", data: changeProfileDetails }) 
    }  
        
    catch(err){
        res.status(500).send({status: false, Error: err.message})
    }
}



  module.exports = {createUser, loginUser, getProfile,updateUserProfile}
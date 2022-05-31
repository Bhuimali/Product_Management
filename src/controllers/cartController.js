const cartModel = require("../models/cartModel")
const userModel = require("../models/userModel")
const productModel = require("../models/productModel")

const  { isValid,isValidBody, validString, isValidObjectId} = require('../utils/validation')


//---------------------------------------------------Post Api------------------------------------------------------

const addCart = async(req, res) => {
    try{
        let data = req.body;
        if (Object.keys(data) == 0) return res.status(400).send({ status: false, message: "Enter a details to add a products" })

        let cartId = data.cartId;
        let productID = data.productId;
        let userID = req.params.userId;

        if(!isValidObjectId(userID)) return res.status(400).send({status: false, message:"Not a valid UserID"})        

        if (!cartId) {
            let checkCart = await cartModel.findOne({ userId: userID })
            if (checkCart) {
                return res.status(400).send({ status: false, message: "Cart already exist for this user. PLease provide cart Id or delete the existing cart" })
            }
        }

        if (cartId) {
            if(!isValidObjectId(cartId)) return res.status(400).send({status: false, message:"Not a valid cartId"})
            let findCart = await cartModel.findById({ _id: cartId })
            if (!findCart)
                return res.status(400).send({ status: false, message: `No cart with this Id - ${cartId}` })
        }

        
        if (!productID) { return res.status(400).send({ status: false, message: "Please provide Product Id " }) }
        if(!isValidObjectId(productID)) return res.status(400).send({status: false, message:"Not a valid productId"})


        if(req.body.quantity) return res.status(400).send({status: false, msg:"Do not need to give quantity"})


        //if (Object.keys userID) == 0) { return res.status(400).send({ status: false, message: "Please provide User Id " }) }
        

        let userExist = await userModel.findOne({ _id: userID });
        if (!userExist) {
            return res.status(404).send({ status: false, message: `No user found with this ${userID}` })
        }


        let cartExist = await cartModel.findOne({ _id: cartId });
      


        if (cartExist) {
            
            if (cartExist.userId != userID) {
                return res.status(403).send({ status: false, message: "This cart does not belong to you. Please check the cart Id" })
            }
            let updateData = {}

            if (cartExist.items.length == 0) {
                let arr = []

                const object = { productId: productID, quantity: 1 }
                arr.push(object)
                updateData["items"] = arr;

                const productPrice = await productModel.findOne({ _id: productID, isDeleted: false }).select({ price: 1, _id: 0 })

                if (!productPrice) { return res.status(404).send({ status: false, mesaage: `No product found with this ${productID}` }) }

                nPrice = productPrice.price;
                updateData['totalPrice'] = cartExist.totalPrice + (nPrice * 1)
                updateData['totalItems'] = arr.length

                const updatedCart = await cartModel.findOneAndUpdate({ _id: cartId }, updateData, { new: true })
                return res.status(200).send({ status: true, message: "product added to cart & Updated Cart", data: updatedCart })
            }

            for (let i = 0; i < cartExist.items.length; i++) {
                if (cartExist.items[i].productId == productID) {
                    // console.log(i)
                    cartExist.items[i].quantity = cartExist.items[i].quantity + 1;

                    updateData['items'] = cartExist.items
                    const productPrice = await productModel.findOne({ _id: productID, isDeleted: false }).select({ price: 1, _id: 0 })
                    if (!productPrice) { return res.status(404).send({ status: false, mesaage: `No product found with this ${productID}` }) }
                    nPrice = productPrice.price;
                    updateData['totalPrice'] = cartExist.totalPrice + (nPrice * 1)
                    updateData['totalItems'] = cartExist.items.length;

                    const updatedCart = await cartModel.findOneAndUpdate({ _id: cartId }, updateData, { new: true })
                    return res.status(200).send({ status: true, message: "product added to cart & Updated Cart", data: updatedCart })
                }
            }
            for (let j = 0; j < cartExist.items.length; j++) {

                if (cartExist.items[j].productId != productID) {
                  
                    const obj = { productId: productID, quantity: 1 }
                    let arr = cartExist.items
                    arr.push(obj)
                    updateData['items'] = arr

                    const productPrice = await productModel.findOne({ _id: productID, isDeleted: false }).select({ price: 1, _id: 0 })
                    if (!productPrice) { return res.status(404).send({ status: false, mesaage: `No product found with this ${productID}` }) }
                    nPrice = productPrice.price
                    updateData['totalPrice'] = cartExist.totalPrice + (nPrice * 1)
                    updateData['totalItems'] = cartExist.items.length;

                    const updatedCart = await cartModel.findOneAndUpdate({ _id: cartId }, updateData, { new: true })
                    return res.status(200).send({ status: true, message: "product added to cart & Updated Cart", data: updatedCart })
                }
            }
        } else {
            let newData = {}
            let arr = []
            newData.userId = userID;

            const object = { productId: productID, quantity: 1 }
            arr.push(object)
            newData.items = arr;

            const productPrice = await productModel.findOne({ _id: productID, isDeleted: false }).select({ price: 1, _id: 0 })
            if (!productPrice) { return res.status(404).send({ status: false, mesaage: `No product found with this ${productID}` }) }

            nPrice = productPrice.price;
            newData.totalPrice = nPrice;

            newData.totalItems = arr.length;

            const newCart = await cartModel.create(newData)

            return res.status(201).send({ status: true, message: "Carcart created and product added to cart successfullyt details", data: newCart })


        }
     }catch(err){
         return res.status(500).send({status: false, Error: err.message})
     }
}


//-----------------------------------------------------update Api--------------------------------------------------

const updateCart = async (req, res) => {
    try{
        const userId = req.params.userId
        const data = req.body

        const {cartId, productId, removeProduct} = data

        //if(!removeProduct) return res.status(400).send({status: false , message: "removeProduct is required"})
        // if(!/^[0|1]+$/.test(removeProduct)) return res.status(400).send({status: false, message:"removeProduct should be 0 when we can remove the product from cart and reduce quantity by 1"})
        if(!(removeProduct == 0 || removeProduct == 1)) return res.status(400).send({status: false, message:"removeProduct should be 0 when we can remove the product from cart and reduce quantity by 1"})


        if(!isValidObjectId(userId)) return res.status(400).send({status: false, message: "userId is not valid userid"})
        const findUser = await userModel.findOne({_id: userId})
        if(!findUser) return res.status(400).send({status: false, message: "user not exist with this userid"})

       if(!isValidObjectId(cartId)) return res.status(400).send({status: false, message: "Invalid CartId"})
        const findCart = await cartModel.findOne({_id: cartId})
        if(!findCart) return res.status(400).send({status: false, messgae: "CartId does not exist"})

        if(!isValidObjectId(productId)) return res.status(400).send({status: false, message: "Invalid ProductId"})
        const findProduct = await productModel.findOne({_id: productId, isDeleted: false})
        if(!findProduct) return res.status(400).send({status: false, messgae: "ProductId does not exist"})


       
        if(removeProduct == 1){
            for (let i = 0; i < findCart.items.length; i++) {
                if (findCart.items[i].productId == productId) {
                    let newPrice = findCart.totalPrice - findProduct.price
                    if(findCart.items[i].quantity >1){
                        findCart.items[i].quantity -= 1
                        let updateCartDetails = await cartModel.findOneAndUpdate({_id: cartId}, {items: findCart.items, totalPrice: newPrice}, {new: true})
                        return res.status(200).send({status: true, message: "cart updated successfully", data: updateCartDetails} )
                    }
                    else{
                        totalItem = findCart.totalItems - 1
                        findCart.items.splice(i, 1)

                        let updatedDetails = await cartModel.findOneAndUpdate({_id: cartId}, {items: findCart.items, totalPrice: newPrice, totalItems: totalItem}, {new: true})
                        return res.status(200).send({status: true, message: "cart removed successfully", data: updatedDetails})
                    }
                }
            }
        }
        if(removeProduct == 0){
            for(let i = 0; i < findCart.items.length; i++){
                if(findCart.items[i].productId == productId){
                    let newPrice = findCart.totalPrice - (findProduct.price * findCart.items[i].quantity)
                    let totalItem = findCart.totalItems - 1
                    findCart.items.splice(i, 1)
                    let updatedCartDetails = await cartModel.findOneAndUpdate({_id: cartId}, {items: findCart.items, totalItems: totalItem, totalPrice: newPrice}, {new: true})
                    return res.status(200).send({status: true, message: "item removed successfully", data: updatedCartDetails})
                }
            }
        }
    }catch(err){
        return res.status(500).send({status: false, Error: err.message})
    }
}

//------------------------------get api-----------------------------------

const getCart = async function (req, res) {

    try {
        let userId = req.params.userId

        const findCart = await cartModel.findOne({ userId: userId })

        if (!findCart) {
            return res.status(400).send({ status: false, message: "User's cart doesn't exist" })
        }

        return res.status(200).send({ status: true, message: "Cart details", data: findCart })
    }
    catch (error) {
        res.status(500).send({ status: false, Error: "Server not responding", message: error.message, });
    }

}

//---------------------------------------delete api-------------------------------------

const deleteCart = async (req, res) => {
    try {
        let userId = req.params.userId

        if (!isValidObjectId(userId)) return res.status(400).send({ status: false, message: "Invalid userId" })

        let findUser = await userModel.findById({ _id: userId })
        if (!findUser) return res.status(400).send({ status: false, message: "userId doesn't exist" })

        let findCart = await cartModel.findById( userId )
        if (!findCart) return res.status(400).send({ status: false, message: "cart doesn't exist by this userId" })

        let cartDeleting = await cartModel.findOneAndUpdate({ userId }, { $set: { items: [], totalPrice: 0, totalItems: 0 } })
        console.log(cartDeleting)
        return res.status(204).send({ status: true, message: "cart deleted Successfully"})

    } catch (err) {
        return res.status(500).send({ status: false, Error: err.message })
    }
}


module.exports = {addCart, updateCart, getCart, deleteCart}




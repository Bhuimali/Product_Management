const AWS= require("aws-sdk")

AWS.config.update({
    accessKeyId: "AKIAY3L35MCRVFM24Q7U",
    secretAccessKey: "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",
    region: "ap-south-1"
  })
  
  //   FILE  CREATION  IN  AWS  S3
  let uploadFile = async (file) => {
    return new Promise(function (resolve, reject) {
        let s3 = new AWS.S3({ apiVersion: '2006-03-01' });
        let uploadParams = {
            ACL: "public-read",
            Bucket: "classroom-training-bucket",
            Key: "abc/" + file.originalname, //HERE
            Body: file.buffer
        };
        s3.upload(uploadParams, function (err, data) {
            if (err) {
                console.log(reject(err))
                return (reject({ "Error": err }))
  
            }
             //console.log(resolve(data))
             //console.log(data);
            console.log("File Uploaded SuccessFully");
            return resolve(data.Location)
        });
  
    });
  
  };
  
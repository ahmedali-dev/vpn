'use strict';
function signingOptions(platform,env=process.env){
 const required=env.TUNNEL_REQUIRE_SIGNING==='1';
 if(platform==='darwin'){
  const values=[env.MAC_SIGN_IDENTITY,env.APPLE_API_KEY_PATH,env.APPLE_API_KEY_ID,env.APPLE_API_ISSUER];
  if(values.some(Boolean)&&!values.every(Boolean))throw Error('Incomplete macOS signing/notarization configuration');
  if(!values.every(Boolean)){if(required)throw Error('macOS release signing credentials are required');return {}}
  return {osxSign:{identity:values[0],hardenedRuntime:true,continueOnError:false},osxNotarize:{appleApiKey:values[1],appleApiKeyId:values[2],appleApiIssuer:values[3]}};
 }
 if(platform==='win32'){
  const values=[env.WIN_CERT_PATH,env.WIN_CERT_PASSWORD];
  if(values.some(Boolean)&&!values.every(Boolean))throw Error('Incomplete Windows signing configuration');
  if(!values.every(Boolean)){if(required)throw Error('Windows release signing credentials are required');return {}}
  return {windowsSign:{certificateFile:values[0],certificatePassword:values[1]}};
 }
 return {};
}
module.exports={signingOptions};

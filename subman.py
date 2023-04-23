import os
import random
import string
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
import stripe
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import httpx
from models import User, Subscription, VerificationCode
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
from loguru import logger
from fastapi import Body
from typing import Dict

load_dotenv()

STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')
MONGODB_CONNECTION_STRING = os.environ.get('MONGODB_CONNECTION_STRING')
MONGODB_DB_NAME = os.environ.get('MONGODB_DB_NAME')
WEBHOOK_URL = os.environ.get('WEBHOOK_URL')


async def get_database():
    try:
        client = AsyncIOMotorClient(MONGODB_URL)
        database = client[DATABASE_NAME]
        logger.info("Connected to database")
        return database
    except ConnectionFailure:
        logger.error("Failed to connect to database")
        raise


print(STRIPE_SECRET_KEY)
print(SENDGRID_API_KEY)
print(STRIPE_WEBHOOK_SECRET)
print(MONGODB_CONNECTION_STRING)
print(MONGODB_DB_NAME)


app = FastAPI()
client = AsyncIOMotorClient(MONGODB_CONNECTION_STRING)
db = client[MONGODB_DB_NAME]

stripe.api_key = STRIPE_SECRET_KEY
sendgrid_client = SendGridAPIClient(SENDGRID_API_KEY)
print(SENDGRID_API_KEY)




# 定义相关的数据模型
class PaymentData(BaseModel):
    user_id: int
    token: str


class UserInput(BaseModel):
    platform_id: str
    platform: str
    email: EmailStr

class UserActivationStatus(BaseModel):
    whatsapp_id: Optional[str]
    telegram_id: Optional[str]
    discord_id: Optional[str]
    line_id: Optional[str]
    activation_status: Dict[str, bool]


async def get_db() -> AsyncIOMotorDatabase:
    return db

async def send_webhook(event_type, data):
    webhook_url = WEBHOOK_URL
    payload = {"type": event_type, "data": data}
    async with httpx.AsyncClient() as client:
        await client.post(webhook_url, json=payload)

#once customer pays, the activation email need to be sent to remind them to active the bot accordingly. the page need to be designed.
def send_confirmation_email(user_email: str, subscription_id: str):
    message = Mail(
        from_email='noreply@mychatgpt.io',
        to_emails='gzxharrison@gmail.com',
        subject='Email Verification',
        html_content='<strong>Your email address has been verified, please active your bot by Verification code via this email</strong>')
    try:
        response = sendgrid_client.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(e.message)

def generate_verification_code() -> str:
    code = ''.join(random.sample(string.digits, k=6))
    return code

def send_verification_email(email: str) -> str:
    code = generate_verification_code() # Removed user_id parameter
    message = Mail(
        from_email="noreply@mychatgpt.io",
        to_emails=email,
        subject="Email Verification",
        plain_text_content=f"Your verification code is: {code}",
    )
    try:
        sendgrid_client.send(message)
        print(code)
        return code
    except Exception as e:
        print(e)
        return e


#when user inputs email address, this interface will be called.
@app.post("/send_verification_code/")
async def send_verification_code(user_input: UserInput, db: AsyncIOMotorDatabase = Depends(get_db)):
    platform_id = user_input.platform_id
    platform = user_input.platform.lower()
    email = user_input.email
    
    # Validate platform
    valid_platforms = ["whatsapp_id", "telegram_id", "discord_id", "line_id"]
    if platform not in valid_platforms:
        return {"is_subscribed": False, "message": "Invalid platform"}

    # Check if the user exists
    user = await db.users.find_one({"email": email})
    if user:
        # Update the user with the platform_id and platform
        await db.users.update_one({"email": email}, {"$set": {platform: platform_id}})
    else:
        return {"is_subscribed": False, "message": "User not found"}

    # Check if the user is subscribed
    if user and user.get("is_subscribed"):
        # Send 6-digit verification code
        verification_code = send_verification_email(email)
        return {"is_subscribed": True, "verification_code": verification_code}
    else:
        return {"is_subscribed": False}


#when user inputs correct verification code, the interface will be called.
@app.post("/update_user_info")
async def update_user_info(user_input: UserInput):
    db = await get_db()
    user_collection = db["users"]

    # 根据提供的电子邮件地址找到用户
    user = await user_collection.find_one({"email": user_input.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    platform = user_input.platform.lower()
    valid_platforms = ["whatsapp_id", "telegram_id", "discord_id", "line_id"]

    if platform not in valid_platforms:
        raise HTTPException(status_code=400, detail="Invalid platform")

    # 检查 platform 和 platform_id 是否匹配
    if user[platform] != user_input.platform_id:
        logger.warning(f"Platform and platform_id do not match for email: {user_input.email}")
        await user_collection.update_one({"email": user_input.email}, {"$set": {platform: user_input.platform_id}})
        user[platform] = user_input.platform_id

    # 返回所有平台及其激活状态
    activation_status = {p: bool(user[p]) for p in valid_platforms}
    user_activation_status = UserActivationStatus(
        whatsapp_id=user["whatsapp_id"],
        telegram_id=user["telegram_id"],
        discord_id=user["discord_id"],
        line_id=user["line_id"],
        activation_status=activation_status
    )

    return user_activation_status


@app.post("/subscribe")
async def subscribe(user_id: int, token: str, plan: str, db=Depends(get_database)):
    user_collection = await get_user_collection()
    user = await user_collection.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # 为不同的订阅方案设置价格
    price_map = {
        "monthly": 999,
        "quarterly": 2499,
        "yearly": 8999
    }

    # 检查订阅方案是否有效
    if plan not in price_map:
        raise HTTPException(status_code=400, detail="Invalid subscription plan")

    try:
        # 使用Stripe创建Charge对象
        charge = stripe.Charge.create(
            amount=price_map[plan], # 订阅价格（以分为单位）
            currency="usd",
            source=token, # 支付令牌
            description=f"Subscription for {plan} plan",
        )

        # 如果付款成功，将用户标记为订阅用户
        if charge.status == "succeeded":
            await user_collection.update_one({"id": user_id}, {"$set": {"subscription": True}})
            return {"message": "Subscription successful"}

    except stripe.error.CardError as e:
        # 如果付款失败，返回错误信息
        raise HTTPException(status_code=400, detail=e.user_message)

@app.post("/cancel_subscription")
async def cancel_subscription(user_id: int, db=Depends(get_database)):
    user_collection = await get_user_collection()
    user = await user_collection.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # 使用Stripe取消订阅
    canceled_subscription = stripe.Subscription.delete(user.subscription_id)
    if canceled_subscription.status == "canceled":
        await user_collection.update_one({"id": user_id}, {"$set": {"subscription": False}})
        return {"message": "Subscription canceled successfully"}
    else:
        raise HTTPException(status_code=400, detail="Failed to cancel subscription")

@app.post("/payment")
async def process_payment(payment_data: PaymentData, db=Depends(get_database)):
    user_collection = await get_user_collection()
    user = await user_collection.find_one({"id": payment_data.user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        charge = stripe.Charge.create(
        amount=1000, # Amount in cents
        currency="usd",
        source=payment_data.token,
        description=f"Subscription payment for user {user.email}"
        )
    except stripe.error.StripeError as e:
        await send_webhook("payment_failure", {"email": user.email})
        raise HTTPException(status_code=400, detail=str(e))
    await user_collection.update_one({"id": user.id}, {"$set": {"subscription": True}})
    await send_webhook("payment_success", {"email": user.email})
    return {"message": "Payment processed successfully"}

@app.post("/verify_email")
async def verify_email(email: str, code: str, platform_id: str, platform: str, db=Depends(get_database)):
    verification_code_collection = await get_verification_code_collection()
    verification_code = await verification_code_collection.find_one({"email": email, "code": code})
    if not verification_code:
        raise HTTPException(status_code=400, detail="Invalid verification code")
    user_collection = await get_user_collection()
    user = await user_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    update_data = {"subscription": True}
    if platform.lower() == "whatsapp":
        update_data["whatsapp_id"] = platform_id
    elif platform.lower() == "telegram":
        update_data["telegram_id"] = platform_id
    elif platform.lower() == "discord":
        update_data["discord_id"] = platform_id
    elif platform.lower() == "line":
        update_data["line_id"] = platform_id
    else:
        raise HTTPException(status_code=400, detail="Invalid platform")
    await user_collection.update_one({"email": email}, {"$set": update_data})
    return {"message": "Email verified and platform ID saved successfully"}
    SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")



@app.post("/stripe_webhook")
async def stripe_webhook(request: Request, db: AsyncIOMotorDatabase = Depends(get_db)):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    print(payload)
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
        user_collection = db["users"]
        subscription_collection = db["subscriptions"]

        event_data = json.loads(payload)
        subscription = event.data.object

        try:
            user_email = subscription["customer_email"]
        except KeyError:
            customer_id = subscription["customer"]
            customer = stripe.Customer.retrieve(customer_id)
            user_email = customer.email
            custom_field1 = customer.get("custom_field1")
            custom_field2 = customer.get("test")
            print(custom_field1)
            print(custom_field2)
            print(user_email)
        try:
            another_email = subscription["metadata"]["another_email"]
        except KeyError:
            another_email = None

        if event.type == "customer.subscription.created":
            user = await user_collection.find_one({"email": user_email})
            if not user:
                user = User(email=user_email)
                result = await user_collection.insert_one(user.dict())

            subscription = Subscription(
                user_email=user_email,
                subscription_id=subscription.id
            )
            result = await subscription_collection.insert_one(subscription.dict())
            subscription.id = result.inserted_id

        # Rest of your code...
        elif event.type == "customer.subscription.updated":
            subscription = event.data.object
            user_email = subscription.customer_email

            user = await user_collection.find_one({"email": user_email})
            if not user:
                user = User(email=user_email)
                result = await user_collection.insert_one(user.dict())

            await subscription_collection.update_one(
                {"subscription_id": subscription.id},
                {"$set": {"user_email": user_email}}
            )

        elif event.type == "customer.subscription.deleted":
            subscription = event.data.object
            await subscription_collection.delete_one({"subscription_id": subscription.id})

        elif event.type == "invoice.payment_succeeded":
            invoice = event.data.object
            user_email = invoice.customer_email

            user = await user_collection.find_one({"email": user_email})
            if user:
                await user_collection.update_one({"email": user_email}, {"$set": {"is_subscribed": True}})
            send_confirmation_email(user_email,subscription.id)

        elif event.type == "invoice.payment_failed":
            invoice = event.data.object
            user_email = invoice.customer_email
            user = await user_collection.find_one({"email": user_email})
            if user:
                await user_collection.update_one({"email": user_email}, {"$set": {"is_subscribed": False}})     
        return {"message": "Webhook received"}
    except ValueError as e:
        # Invalid payload
        raise HTTPException(status_code=400, detail=str(e))
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        raise HTTPException(status_code=400, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

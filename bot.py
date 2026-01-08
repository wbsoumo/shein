import telebot
from telebot import types
import requests
import random
import json
import os
import uuid
import re
from urllib.parse import urlencode, unquote

BOT_TOKEN = '8539197930:AAFZ4YZ4DX5nzv8SVgoqYir2ZWJSlth1_Zg' # change karo isko @BotFather se new token banake!
COOKIES_FILE = 'cookies.json' # no need to change
AD_ID = '968777a5-36e1-42a8-9aad-3dc36c3f77b2' # no need to change

bot = telebot.TeleBot(BOT_TOKEN)

user_states = {}

def get_random_ip():
    """Generate random IP for headers"""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

def get_android_headers(additional_headers=None):
    """Get Android headers for API calls"""
    headers = {
        'User-Agent': 'Android',
        'Client_type': 'Android/29',
        'Client_version': '1.0.8',
        'X-Tenant-Id': 'SHEIN',
        'X-Tenant': 'B2C',
        'Ad_id': AD_ID,
        'X-Forwarded-For': get_random_ip(),
        'Host': 'api.sheinindia.in',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }
    if additional_headers:
        headers.update(additional_headers)
    return headers

def decode_cookies(cookies_dict):
    """Decode URL encoded cookies"""
    return {k: unquote(v) if isinstance(v, str) else v for k, v in cookies_dict.items()}

def get_web_headers():
    """Get web headers for order fetching"""
    return {
        'authority': 'www.sheinindia.in',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
        'referer': 'https://www.sheinindia.in/my-account/orders',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36'
    }

def is_logged_in():
    """Check if user is logged in"""
    return os.path.exists(COOKIES_FILE) and os.path.getsize(COOKIES_FILE) > 0

def get_current_account():
    """Get current logged in account"""
    if not is_logged_in():
        return None
    
    try:
        with open(COOKIES_FILE, 'r') as f:
            data = json.load(f)
            if data:
                mobile = list(data.keys())[0]
                return {
                    'mobile': mobile,
                    'cookies': data[mobile],
                    'uid': data[mobile].get('U', 'N/A')
                }
    except:
        pass
    return None

def clear_cookies():
    """Clear all cookies"""
    if os.path.exists(COOKIES_FILE):
        os.remove(COOKIES_FILE)
    return True

def get_client_token(session):
    """Get client token for authentication"""
    url = "https://api.sheinindia.in/uaas/jwt/token/client"
    headers = get_android_headers({'Content-Type': 'application/x-www-form-urlencoded'})
    data = "grantType=client_credentials&clientName=trusted_client&clientSecret=secret"
    resp = session.post(url, data=data, headers=headers)
    try:
        return resp.json().get('access_token') if resp.status_code == 200 else None
    except:
        return None

def get_ei_token(session, client_token, phone_number):
    """Get encrypted ID token"""
    url = "https://api.sheinindia.in/uaas/accountCheck"
    params = {'client_type': 'Android/29', 'client_version': '1.0.8'}
    headers = get_android_headers({
        'Authorization': f'Bearer {client_token}',
        'Requestid': 'account_check',
        'Content-Type': 'application/x-www-form-urlencoded'
    })
    data = f'mobileNumber={phone_number}'
    
    resp = session.post(url, headers=headers, data=data, params=params, timeout=10)
    try:
        res_json = resp.json()
        if res_json:
            if 'encryptedId' in res_json: return res_json['encryptedId']
            d = res_json.get('data') or res_json.get('result') or {}
            if isinstance(d, dict): return d.get('encryptedId', "")
    except:
        pass
    return ""

def send_otp(session, c_token, mobile):
    """Send OTP to mobile number"""
    url = "https://api.sheinindia.in/uaas/login/sendOTP?client_type=Android%2F29&client_version=1.0.8"
    headers = get_android_headers({
        'Authorization': f'Bearer {c_token}', 
        'Content-Type': 'application/x-www-form-urlencoded'
    })
    resp = session.post(url, data=f"mobileNumber={mobile}", headers=headers)
    return resp.status_code == 200

def verify_otp_full(session, c_token, mobile, otp):
    """Verify OTP and get authentication tokens"""
    url = "https://api.sheinindia.in/uaas/login/otp?client_type=Android%2F29&client_version=1.0.8"
    headers = get_android_headers({
        'Authorization': f'Bearer {c_token}', 
        'Content-Type': 'application/x-www-form-urlencoded'
    })
    params = {
        'adId': AD_ID, 'clientName': 'trusted_client', 'expireOTP': 'true',
        'mobileNumber': 'true', 'otp': otp, 'clientSecret': 'secret',
        'grantType': 'password', 'deviceId': str(uuid.uuid4()), 'username': mobile
    }
    resp = session.post(url, data=urlencode(params), headers=headers)
    try:
        return resp.json() if resp.status_code == 200 else None
    except:
        return None

def fetch_profile_uid(session, access_token):
    """Get user profile UID"""
    url = "https://api.sheinindia.in/uaas/users/current?client_type=Android%2F29&client_version=1.0.8"
    headers = get_android_headers({
        'Authorization': f'Bearer {access_token}',
        'Requestid': 'UserProfile'
    })
    
    try:
        resp = session.get(url, headers=headers, timeout=10)
        data = resp.json()
        
        if data:
            if 'uid' in data:
                return data['uid']
            elif 'data' in data and 'uid' in data['data']:
                return data['data']['uid']
    except:
        pass
    return None

def save_cookies(mobile, auth_response, ei_value, uid_value):
    """Save cookies to cookies.json file"""
    cookies_dict = {
        'V': '1',
        '_fpuuid': str(uuid.uuid4()).replace('-', '')[:21],
        'deviceId': str(uuid.uuid4()),
        'storeTypes': 'shein',
        'LS': 'LOGGED_IN',
        'C': str(uuid.uuid4()),
        'EI': ei_value,
        'A': auth_response.get('access_token', ''),
        'U': uid_value if uid_value else f"{mobile}@sheinindia.in",
        'R': auth_response.get('refresh_token', '')
    }

    all_data = {mobile: cookies_dict}
    with open(COOKIES_FILE, 'w') as f:
        json.dump(all_data, f, indent=4)
    
    return cookies_dict

def fetch_orders_for_user(cookies_dict, chat_id):
    """Fetch orders using saved cookies"""
    try:
        status_msg = bot.send_message(chat_id, "âœ… **Starting Order Fetch...**\nâ”â”â”â”â”â”â”â”â”â”â”â”â”â”â”\nðŸ“„ Page: 0\nðŸ“¦ Orders Found: 0", parse_mode="Markdown")
        
        session = requests.Session()
        session.headers.update(get_web_headers())
        session.cookies.update(decode_cookies(cookies_dict))

        page = 0
        total_found = 0
        all_summary = {"total": 0, "delivered": 0, "canceled": 0, "no_coupon": 0}
        
        canceled_coupons = set()
        total_coupons_count = 0
        
        orders_report = "âœ… Shein Full Orders Report\n" + "="*45 + "\n\n"

        while True:
            try:
                url = f'https://www.sheinindia.in/my-account/orders?page={page}'
                response = session.get(url, timeout=30)
                
                if response.status_code != 200 or "No orders placed" in response.text:
                    break

                match = re.search(r'window\.__PRELOADED_STATE__\s*=\s*({.*?});', response.text, re.DOTALL)
                if not match: 
                    break

                state_data = json.loads(match.group(1))
                orders_root = state_data.get('ordersData', {}).get('ordersData', {})
                order_list = orders_root.get('order_list', [])

                if not order_list: 
                    break

                for order in order_list:
                    all_summary["total"] += 1
                    total_found += 1 
                    
                    oid = order.get('orderId', 'N/A')
                    odate = order.get('orderDate', 'N/A')
                    amt = order.get('totalAmount', 0)
                    pmode = order.get('paymentMode', 'N/A')
                    placed_via = order.get('orderPlacedAt', 'Web')
                    
                    items_data = order.get('orderItemLines', [])
                    main_status = items_data[0].get('newStatus', 'UNKNOWN') if items_data else "N/A"
                    
                    is_canceled = "CANCEL" in main_status.upper()
                    
                    if "DELIVERED" in main_status.upper(): 
                        all_summary["delivered"] += 1
                    elif is_canceled: 
                        all_summary["canceled"] += 1

                    vouchers = order.get('vouchers', [])
                    order_coupons = [v.get('voucherCode') for v in vouchers if v.get('voucherCode')]
                    
                    if not order_coupons:
                        all_summary["no_coupon"] += 1
                    else:
                        total_coupons_count += len(order_coupons)
                        if is_canceled:
                            canceled_coupons.update(order_coupons)

                    status_emoji = "âœ…" if "DELIVERED" in main_status.upper() else "âŒ" if is_canceled else "ðŸ“¦"
                    orders_report += f"{status_emoji} Order ID: {oid}\n"
                    orders_report += f"ðŸ“… Date: {odate}\n"
                    orders_report += f"ðŸ’° Total: {amt} INR | ðŸ’³ Method: {pmode}\n"
                    orders_report += f"ðŸ“± Source: {placed_via} | ðŸ“ Status: {main_status}\n"
                    if order_coupons:
                        orders_report += f"ðŸŽ« Coupons: {', '.join(order_coupons)}\n"

                    orders_report += "ðŸ›’ Product Details:\n"
                    for item in items_data:
                        orders_report += f"   - {item.get('title', 'Item')} (Qty: {item.get('quantity')}) | Price: {item.get('unitPrice')}\n"
                    orders_report += "-"*40 + "\n"

                try:
                    bot.edit_message_text(
                        chat_id=chat_id,
                        message_id=status_msg.message_id,
                        text=f"ðŸš€ Fetching Started...\nâ”â”â”â”â”â”â”â”â”â”â”â”â”â”â”\nðŸ“„ **Total Page:** {page}\nðŸ“¦ **Orders:** {total_found}\nðŸŽŸï¸ **Canceled Coupons:** {len(canceled_coupons)}",
                        parse_mode="Markdown"
                    )
                except: 
                    pass

                page += 1

            except Exception as e:
                bot.send_message(chat_id, f"âŒ Error during fetching: {str(e)}")
                break

        bot.edit_message_text("âœ… Fetching Completed!", chat_id, status_msg.message_id)

        orders_file = f"orders_{chat_id}.txt"
        with open(orders_file, "w", encoding="utf-8") as f:
            f.write(orders_report)
        with open(orders_file, "rb") as f:
            bot.send_document(chat_id, f, caption="ðŸ›ï¸ Full Orders Report")
        os.remove(orders_file)

        summary_msg = (
            f"â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”\n"
            f"ðŸ“¦ Total Orders: {all_summary['total']}\n"
            f"âœ… Delivered: {all_summary['delivered']}\n"
            f"âŒ Canceled: {all_summary['canceled']}\n"
            f"ðŸŽŸï¸ Total Coupons: {total_coupons_count}\n"
            f"ðŸš« Not Applied: {all_summary['no_coupon']}\n"
            f"âŒ Canceled Coupons: {len(canceled_coupons)}"
        )
        bot.send_message(chat_id, summary_msg, parse_mode="Markdown")
        
        if canceled_coupons:
            coupons_file = f"canceled_coupons_{chat_id}.txt"
            with open(coupons_file, "w", encoding="utf-8") as f:
                f.write("\n".join(canceled_coupons))
            with open(coupons_file, "rb") as f:
                bot.send_document(chat_id, f, caption="ðŸŽŸï¸ Canceled Coupons")
            os.remove(coupons_file)
        
    except Exception as e:
        bot.send_message(chat_id, f"âŒ Error in order fetching: {str(e)}")
        
def get_main_keyboard():
    """Get appropriate keyboard based on login status"""
    markup = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    
    if is_logged_in():
        account = get_current_account()
        fetch_btn = types.KeyboardButton('ðŸš€ Fetch Orders')
        logout_btn = types.KeyboardButton('ðŸ”“ Logout')
        markup.add(fetch_btn, logout_btn)
    else:
        login_btn = types.KeyboardButton('ðŸ” Login')
        markup.add(login_btn)
    
    return markup

def update_keyboard(chat_id):
    """Update keyboard for specific user"""
    try:
        markup = get_main_keyboard()
        bot.send_message(chat_id, "ðŸ”„ Keyboard updated!", reply_markup=markup)
    except:
        pass

@bot.message_handler(func=lambda message: True)
def handle_all_messages(message):
    """Handle all messages"""
    text = message.text
    
    if text == '/start' or text == 'Home':
        account = get_current_account()
        
        if account:
            welcome_msg = (
                f"Welcome back!\n\n"
                f"ðŸ“± **Logged in as:** {account['mobile']}\n"
                f"ðŸ†” **Email:** {account['uid']}\n\n"
                f"Select an option:"
            )
        else:
            welcome_msg = (
                "Welcome to SHEIN Bot!\n\n"
                "ðŸš€ **Fetch Orders**: Fetch your order history\n\n"
                "Please select an option:"
            )
        
        bot.reply_to(message, welcome_msg, reply_markup=get_main_keyboard(), parse_mode="Markdown")
    
    elif text == 'ðŸ” Login':
        if is_logged_in():
            bot.send_message(message.chat.id, "âœ… Already logged in! Use 'ðŸš€ Fetch Orders' to get your orders.", reply_markup=get_main_keyboard())
        else:
            user_states[message.chat.id] = {'step': 'waiting_for_mobile'}
            bot.send_message(message.chat.id, "Please enter your mobile number:")
    
    elif text == 'ðŸš€ Fetch Orders':
        if not is_logged_in():
            bot.send_message(message.chat.id, "âŒ Please login first!", reply_markup=get_main_keyboard())
            return
        
        account = get_current_account()
        bot.send_message(message.chat.id, f"âœ… Fetching orders for {account['mobile']}...")
        fetch_orders_for_user(account['cookies'], message.chat.id)
    
    elif text == 'ðŸ”“ Logout':
        if is_logged_in():
            account = get_current_account()
            clear_cookies()
            bot.send_message(message.chat.id, 
                            f"âœ… Logged out successfully!\n"
                            f"ðŸ“± Account: {account['mobile']}\n\n"
                            f"You can now login with a new account.",
                            reply_markup=get_main_keyboard())
        else:
            bot.send_message(message.chat.id, "âŒ Not logged in!", reply_markup=get_main_keyboard())
    
    elif user_states.get(message.chat.id, {}).get('step') == 'waiting_for_mobile':
        mobile = message.text.strip()
        if not mobile.isdigit() or len(mobile) != 10:
            bot.send_message(message.chat.id, "âŒ Invalid mobile number. Please enter a valid 10-digit number:")
            return
        
        user_states[message.chat.id] = {
            'step': 'waiting_for_otp',
            'mobile': mobile,
            'session': requests.Session()
        }
        
        session = user_states[message.chat.id]['session']
        
        try:
            c_token = get_client_token(session)
            if not c_token:
                bot.send_message(message.chat.id, "âŒ Failed to get client token. Please try again.")
                del user_states[message.chat.id]
                return
            
            if send_otp(session, c_token, mobile):
                user_states[message.chat.id]['c_token'] = c_token
                bot.send_message(message.chat.id, f"âœ… OTP sent to {mobile}. Please enter the OTP:")
            else:
                bot.send_message(message.chat.id, "âŒ Failed to send OTP. Please try again.")
                del user_states[message.chat.id]
                
        except Exception as e:
            bot.send_message(message.chat.id, f"âŒ Error: {str(e)}")
            del user_states[message.chat.id]
    
    elif user_states.get(message.chat.id, {}).get('step') == 'waiting_for_otp':
        otp = message.text.strip()
        if not otp.isdigit() or len(otp) != 4:
            bot.send_message(message.chat.id, "âŒ Invalid OTP. Please enter a valid 4-digit OTP:")
            return
        
        user_data = user_states[message.chat.id]
        mobile = user_data['mobile']
        session = user_data['session']
        c_token = user_data['c_token']
        
        try:
            auth_data = verify_otp_full(session, c_token, mobile, otp)
            if auth_data:
                ei_value = get_ei_token(session, c_token, mobile)
                acc_token = auth_data.get('access_token')
                uid_from_api = fetch_profile_uid(session, acc_token)
                save_cookies(mobile, auth_data, ei_value, uid_from_api)
                
                bot.send_message(message.chat.id, 
                                f"âœ… **Login Successful!**\n"
                                f"ðŸ“± Account: {mobile}\n"
                                f"ðŸ†” UID: {uid_from_api}\n\n"
                                f"Now you can use 'ðŸš€ Fetch Orders' to get your order history.",
                                reply_markup=get_main_keyboard(),
                                parse_mode="Markdown")
            else:
                bot.send_message(message.chat.id, "âŒ Invalid OTP or login failed. Please try again.", reply_markup=get_main_keyboard())
        except Exception as e:
            bot.send_message(message.chat.id, f"âŒ Error during login: {str(e)}", reply_markup=get_main_keyboard())
        del user_states[message.chat.id]
    else:
        bot.send_message(message.chat.id, "Please use the buttons below:", reply_markup=get_main_keyboard())

if __name__ == "__main__":
    print("Bot is started...")
    print("ðŸ“ Cookies file:", COOKIES_FILE)
    
    user_states.clear()
    bot.polling()





Is code se kya hoga english me bolo

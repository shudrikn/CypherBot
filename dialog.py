import sys
from enum import Enum
import json
import threading
import time

import telebot
from telebot import types

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad,unpad

char_read_time = 2

use_counter=0

# Создаем экземпляр бота
bot = telebot.TeleBot(token = sys.argv[1], threaded=False, num_threads=1)

class CryptoOperations(int, Enum):
    unknown = 0
    encrypt = 1
    decrypt = 2

smiles = "💔😀😁🤣🙃😊😍😗😜🤑🤔🤨😶🌫🙄💨😔😴🤕🤧🥴🥳🤓😮😳😦😰😭😣😩😤🤬💀👹👽😺😻🙀🙈💋💝💓💟💚💯💫🕳👁🗯🐵🐩🦝🐈🐅🐎🦌🐂🐷🐽🐐🦙🐭🐹🐿🦇🐨🐾🐓🐥🕊🦢🦜🐢🐲🦖🐬🐠🐙🦋🐝🦗🕸💐🥀🌼🌴🌿🍂🍇🍊🍍🍏🍒🥝🥥🥔🌶🥬🍄🌰🥖🥯🧀🥩🍟🥪🍳🥣🍱🍚🍝🍣🥮🥠🦞🍨🎂🥧🍭🍼🍵🍷🍺🥃🥢🥄🏺🌏🗾🌋🏖🏞🏗🏚🏢🏥🏩🏬🏰🗽🕍🌃🌅🌉🎢🚂🚅🚈🚝🚌🚐🚓🚖🚙🚛🏍🛴🚏🛢🚥🚧🛳🛩🚟🛰🛎🕛🕜🕒🌒🌕🌘🌛🌝🌟🌤🌧🌪🌀🔥🎃🎇🎉🎍🎐🎀🎟🏆🥈🏀🏉🎳🏒🏸🥅🎽🥌🎮🎲🃏🎭🧵🥽👔🧣🧦👙👜🎒👟👠👢🎩📿💎🔉📣🔕🎶🎛📻🎸🎻📱📟🖥🖲💿🎥🎬😃😆😂😇🤩😚😋🤪🤗😐😏😬🤥😪😷🤢🥵😵🤯🧐😟😯🥺😧😥😱"

def encryption_key_from_pass(key):
    h = SHA256.new()
    h.update(key.encode("utf-8"))
    return h.digest()

def bytes_to_printable_string(bytes):
    result = ""

    for byte in bytes:
        result = result + smiles[byte]

    return result

def printable_string_to_bytes(string):
    result = []

    for char in string:
        ind = smiles.index(char)
        result.append(ind)

    return bytes(result)

def encrypt(plaintext, key):
    plaintext_bytes = plaintext.encode("utf-8")

    encryption_key = encryption_key_from_pass(key)
    
    iv = Random.new().read(AES.block_size)

    cipher = AES.new(encryption_key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(plaintext_bytes)
    ciphertext = iv + ciphertext

    return bytes_to_printable_string(ciphertext)

def decrypt(encoded_ciphertext, key):
    try:
        ciphertext = printable_string_to_bytes(encoded_ciphertext)
    except:
        return "Это точно не зашифрованное сообщение"

    encryption_key = encryption_key_from_pass(key)
    iv = ciphertext[0:AES.block_size:]
    cipher = AES.new(encryption_key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size::])

    try:
        return plaintext.decode("utf-8")
    except:
        return "Неверный пароль"

class Dialog:
    def __init__(self, chat_id):
        self.chat_id = chat_id
        self.data = ""
        self.key = ""
        self.operation = CryptoOperations.unknown
        self.action = None
        self.previosly_message = None
        self.show_choose_operation_buttons()
        
    def delete_prev_message(self):
        if self.previosly_message:
            bot.delete_message(self.chat_id, self.previosly_message)
            self.previosly_message = None

    def show_choose_operation_buttons(self):
        # Добавляем две кнопки
        markup = types.InlineKeyboardMarkup()
        buttonA = types.InlineKeyboardButton('Зашифровать', callback_data=json.dumps(CryptoOperations.encrypt))
        buttonB = types.InlineKeyboardButton('Расшифровать', callback_data=json.dumps(CryptoOperations.decrypt))

        markup.row(buttonA, buttonB)
        self.action = self.choose_operation
        self.previosly_message = bot.send_message(self.chat_id, 'Выбери операцию', reply_markup=markup).message_id

    def choose_operation(self, operation):
        try:
            self.operation = json.loads(operation)
            self.action = self.get_data
            self.delete_prev_message()
            if self.operation == CryptoOperations.encrypt:
                message = 'Напиши текст который хочешь защитить'
            elif self.operation == CryptoOperations.decrypt:
                message = 'Перешли мне сообщение, которое нужно прочитать'
            self.previosly_message = bot.send_message(self.chat_id, message).message_id
            
        except:
            pass

    def get_data(self, data):
        if not hasattr(data, 'text'):
            return
        self.data = data.text
        self.action = self.get_key
        self.delete_prev_message()
        self.previosly_message = bot.send_message(self.chat_id, 'Введи пароль').message_id
    
    def get_key(self, key):
        if not hasattr(key, 'text'):
            return
        self.key = key.text.lower()

        response = ""
        if self.operation == CryptoOperations.encrypt:
            response = encrypt(self.data,self.key)
            result_deletion_delay = 30
        elif self.operation == CryptoOperations.decrypt:
            response = decrypt(self.data,self.key)
            result_deletion_delay = char_read_time * len(response)

        self.delete_prev_message()
        result_message_id = bot.send_message(self.chat_id, response, protect_content=False).message_id
        t=threading.Timer(result_deletion_delay, lambda message_id: bot.delete_message(self.chat_id, message_id), [result_message_id])
        t.start()

        global use_counter 
        use_counter = use_counter + 1
        print(use_counter)

        self.show_choose_operation_buttons()

    def reminder(self):
        message = 'Не забывай про безопасность своей переписки! Введи /start чтобы продолжить пользоваться ботом.'
        bot.send_message(self.chat_id, message).message_id


handlers = {}

# Функция, обрабатывающая команду /start
@bot.message_handler(commands=["start"])
def start(message):
    chat_id = message.chat.id
    handlers[chat_id] = Dialog(chat_id)

# Получение сообщений от юзера
@bot.message_handler(content_types=["text"])
def handle_text(message):
    chat_id = message.chat.id
    if not(chat_id in handlers):
        handlers[chat_id] = Dialog(chat_id)
    handlers[chat_id].action(message)
    bot.delete_message(chat_id, message.id)

@bot.callback_query_handler(func=lambda call: True)
def handle(call):
    chat_id = call.message.chat.id

    handle = handlers.get(chat_id)
    if handle != None:
        handlers[chat_id].action(call.data)

# Запускаем бота
while True:
        try:
            bot.polling(none_stop=True, interval=0)
        except Exception as e:
            time.sleep(3)
            print("Exception: ")
            print(e)
            # for dialog in handlers:
            #     dialog.reminder();

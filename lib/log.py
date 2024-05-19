from datetime import datetime



class Log:
    log_dict = {"INFO": [], "ERROR": [], "VULNERABILITY": []}

    @classmethod
    def clear_log(cls):
        cls.log_dict = {"INFO": [], "ERROR": [], "VULNERABILITY": []}

    @classmethod
    def info(cls, text):
        log_text = "[" + datetime.now().strftime("%H:%M:%S") + "] [INFO] " + text
        cls.log_dict["INFO"].append(log_text)
        print(log_text)

    @classmethod
    def error(cls, text):
        log_text = "[" + datetime.now().strftime("%H:%M:%S") + "] [ERROR] " + text
        cls.log_dict["ERROR"].append(log_text)
        print(log_text)

    @classmethod
    def alert(cls, text):
        log_text = "[" + datetime.now().strftime("%H:%M:%S") + "] [VULNERABILITY] " + text
        cls.log_dict["VULNERABILITY"].append(log_text)
        print(log_text)
def convert(useronu):
    # Метод конвертирует МАК ОНУ в десятичный формат
        outmacdec = ""
        n = 2
        out = [useronu[i:i+n] for i in range(0, len(useronu), n)]

        for i in out:
            dece = int(i, 16)
            outmacdec = outmacdec + "." + str(dece)

        return outmacdec

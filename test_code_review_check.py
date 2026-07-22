"""Arquivo temporario so pra testar o workflow de code review -- sera removido."""

def calcular_media(valores):
    total = 0
    for v in valores:
        total += v
    return total / len(valores)  # bug proposital: ZeroDivisionError se a lista for vazia


def buscar_usuario(usuarios, email):
    for u in usuarios:
        if u["email"] == email:
            return u
    return None

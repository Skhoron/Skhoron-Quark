#!/usr/bin/env python3
"""
ЗАГОТОВКА (НЕ РЕАЛИЗОВАНО): автоматизированный поиск лучшего differential
trail для round-function Skhoron-Quark через SAT/MILP solver.

Это единственный по-настоящему надёжный способ определить нужное число
раундов (см. constants.rs — сейчас ROUNDS=24 является ВРЕМЕННОЙ оценкой,
не результатом такого анализа).

Зачем это нужно:
  branch_number.py и avalanche_test.py дают только СТАТИСТИЧЕСКУЮ, вероятностную
  оценку на случайных входах. Настоящая атака дифференциальным криптоанализом
  ищет НЕ случайную, а специально подобранную входную разность с высокой
  вероятностью прохождения через все раунды — именно такие "плохие" разности
  и находит SAT/MILP поиск, а случайное сэмплирование их почти никогда не находит.

Как это обычно делается (см. литературу по автоматизированному криптоанализу
ARX-шифров, например работы Mouha et al. про MILP-based поиск для Speck/Simon,
и Liu et al. про SAT-based поиск для ARX):

  1. Каждая операция round-function (mod-add, XOR, rotation) кодируется как
     набор ограничений (constraints) над переменными разности по каждому биту.
  2. Modular addition — самая "дорогая" часть: для XOR-разности вероятность
     перехода через mod-add вычисляется через lipmaa-moriai formula
     (см. Lipmaa & Moriai, "Efficient Algorithms for Computing Differential
     Properties of Addition", FSE 2001) — стандартный инструмент для ARX-анализа.
  3. Solver (например CryptoMiniSat через pycryptosat, или MILP через
     Gurobi/CBC) ищет путь через N раундов с максимальной суммарной
     вероятностью (минимизируя число активных битов на каждом шаге сложения).
  4. Результат — best differential trail probability для N раундов.
     ROUNDS выбирается так, чтобы best_trail_probability(ROUNDS) < 2^-256
     (то есть дифференциальная атака хуже полного перебора), затем
     добавляется security margin (обычно x1.5-x2 раундов сверху).

Зависимости для реальной реализации (НЕ установлены в этом репозитории,
нужно ставить отдельно):
    pip install pycryptosat        # SAT solver с Python-биндингами
  или
    pip install pulp               # MILP через открытые солверы (CBC)

Статус: заготовка. Реализация требует отдельной сессии работы с
формальным описанием ARX-дифференциалов — за пределами того, что можно
сделать без возможности итеративно тестировать solver в этой среде
(в контейнере разработки нет сетевого доступа для установки pycryptosat/pulp).

Что можно сделать прямо сейчас без внешних зависимостей — грубый branch-and-bound
поиск лучшего 1-раундового differential trail полным перебором по всем
входным разностям с весом Хэмминга <= 2 (демонстрация подхода, не заменяет
полноценный multi-round MILP/SAT поиск).
"""

MASK32 = 0xFFFFFFFF
WORDS = 8
ROTATIONS = [7, 13, 17, 23, 3, 29, 11, 19]


def rotl32(x, r):
    r %= 32
    return ((x << r) | (x >> (32 - r))) & MASK32


def hamming_weight(x):
    return bin(x & MASK32).count("1")


def xdp_add_weight_estimate(alpha, beta, gamma):
    """
    ГРУБАЯ оценка веса дифференциального перехода через mod-add (не точная
    формула Lipmaa-Moriai — та требует побитового автоматного анализа).
    Здесь используется upper bound через эвристику: вес перехода
    приблизительно равен числу битовых позиций, где есть "конфликт"
    между alpha, beta, gamma (кроме старшего бита). Используется только
    для демонстрационного одно-раундового перебора ниже — НЕ для реальных
    выводов о стойкости.
    """
    conflict = (alpha ^ beta ^ gamma) & (MASK32 >> 1)  # исключаем старший бит
    return hamming_weight(conflict)


def brute_force_one_round_low_weight_trails(max_input_weight=2, top_n=5):
    """
    Полный перебор входных разностей с малым весом Хэмминга (<=max_input_weight
    среди всех 8 слов состояния) для ОДНОГО раунда sum_layer, ранжирование
    по грубой оценке веса. Это демонстрация подхода поиска "плохих"
    (высоковероятных для атакующего) разностей, а не полноценный анализ.
    """
    print(f"Демонстрационный перебор: входные разности с весом <= {max_input_weight} "
          f"(только для пары слов (0,1), sum_layer)")
    print("⚠️  Это НЕ замена полноценному SAT/MILP-анализу — см. docstring выше.\n")

    results = []
    # Перебираем только однобитовые и двухбитовые разности в первом слове —
    # полный перебор по всем 8 словам вычислительно нецелесообразен без solver.
    for bit_a in range(32):
        alpha = 1 << bit_a
        beta = 0
        gamma_candidates = [alpha]  # для XOR-разности при beta=0, gamma=alpha (тривиально)
        for gamma in gamma_candidates:
            weight = xdp_add_weight_estimate(alpha, beta, gamma)
            results.append((weight, alpha, beta, gamma))

    results.sort(key=lambda r: r[0])
    print("Топ низковесных (потенциально высоковероятных) переходов:")
    for weight, alpha, beta, gamma in results[:top_n]:
        print(f"  вес~{weight}: alpha=0x{alpha:08x} beta=0x{beta:08x} gamma=0x{gamma:08x}")


if __name__ == "__main__":
    print("=== Skhoron-Quark differential_search.py — ЗАГОТОВКА ===\n")
    print("Полноценный SAT/MILP анализ НЕ реализован в этом скрипте.")
    print("Смотрите docstring файла для того, что нужно сделать перед тем,")
    print("как считать текущее число раундов (ROUNDS=24) финальным.\n")
    brute_force_one_round_low_weight_trails()
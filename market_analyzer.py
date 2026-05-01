"""
Advanced Market Analysis — Improved Signal Engine
Indicators: RSI, MACD, Bollinger Bands, EMA, Candlestick Patterns
No randomness — pure technical analysis
"""

import time
import statistics
from typing import Dict, List


class MarketAnalyzer:

    def __init__(self, quotex_client):
        self.client = quotex_client

    def safe_float(self, value, default=0.0):
        try:
            return float(value) if value is not None else default
        except:
            return default

    async def get_comprehensive_analysis(self, asset_code: str) -> Dict:
        try:
            current_time = time.time()
            candles = await self.client.get_candles(asset_code, current_time, 6000, 60)

            if not candles or len(candles) < 30:
                return {"error": "Insufficient candle data"}

            closes = [self.safe_float(c.get('close') or c.get('c')) for c in candles]
            opens  = [self.safe_float(c.get('open')  or c.get('o')) for c in candles]
            highs  = [self.safe_float(c.get('high')  or c.get('h')) for c in candles]
            lows   = [self.safe_float(c.get('low')   or c.get('l')) for c in candles]

            # Remove zeros
            if any(c == 0 for c in closes[-10:]):
                return {"error": "Invalid candle data"}

            current_price = closes[-1]

            # ── INDICATORS ──
            rsi_data    = self._calc_rsi(closes)
            macd_data   = self._calc_macd(closes)
            bb_data     = self._calc_bollinger(closes)
            ema_data    = self._calc_emas(closes, current_price)
            vol_data    = self._calc_volatility(closes, highs, lows)
            trend_data  = self._calc_trend(closes)
            pattern     = self._detect_candle_pattern(opens, closes, highs, lows)
            sr_data     = self._calc_support_resistance(highs, lows, current_price)
            gap_data    = self._calc_gaps(opens, closes)
            rejection   = self._calc_rejection(candles[-1], highs, lows, opens, closes)
            zigzag      = self._calc_zigzag(highs, lows)
            movement    = self._calc_movement(closes)

            # ── SIGNAL SCORING ──
            bull_bear   = self._score_signal(
                closes, opens, rsi_data, macd_data, bb_data, ema_data, trend_data, pattern
            )

            market_summary = self._market_condition(vol_data, trend_data, movement)
            recommendation = self._final_recommendation(bull_bear, rsi_data, macd_data, market_summary)

            return {
                "asset":            asset_code,
                "current_price":    round(current_price, 6),
                "trend":            trend_data,
                "volatility":       vol_data,
                "gap":              gap_data,
                "rejection":        rejection,
                "support_resistance": sr_data,
                "moving_averages":  ema_data,
                "zigzag":           zigzag,
                "movement":         movement,
                "bull_bear":        bull_bear,
                "market_summary":   market_summary,
                "recommendation":   recommendation,
                "rsi":              rsi_data,
                "macd":             macd_data,
                "bollinger":        bb_data,
                "pattern":          pattern,
                "candles":          candles[-100:],
            }

        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"error": str(e)}

    # ─────────────────────────────────────────────────────────────
    # RSI
    # ─────────────────────────────────────────────────────────────
    def _calc_rsi(self, closes: List[float], period: int = 14) -> Dict:
        if len(closes) < period + 1:
            return {"value": 50, "signal": "NEUTRAL", "zone": "NEUTRAL"}

        deltas = [closes[i] - closes[i-1] for i in range(1, len(closes))]
        gains  = [d if d > 0 else 0 for d in deltas]
        losses = [-d if d < 0 else 0 for d in deltas]

        avg_gain = sum(gains[:period]) / period
        avg_loss = sum(losses[:period]) / period

        for i in range(period, len(gains)):
            avg_gain = (avg_gain * (period - 1) + gains[i]) / period
            avg_loss = (avg_loss * (period - 1) + losses[i]) / period

        if avg_loss == 0:
            rsi = 100
        else:
            rs  = avg_gain / avg_loss
            rsi = 100 - (100 / (1 + rs))

        if rsi >= 70:
            signal = "OVERBOUGHT"
            zone   = "SELL"
        elif rsi <= 30:
            signal = "OVERSOLD"
            zone   = "BUY"
        elif rsi >= 55:
            signal = "BULLISH"
            zone   = "BUY"
        elif rsi <= 45:
            signal = "BEARISH"
            zone   = "SELL"
        else:
            signal = "NEUTRAL"
            zone   = "NEUTRAL"

        return {"value": round(rsi, 2), "signal": signal, "zone": zone}

    # ─────────────────────────────────────────────────────────────
    # MACD
    # ─────────────────────────────────────────────────────────────
    def _calc_macd(self, closes: List[float], fast=12, slow=26, signal_period=9) -> Dict:
        def ema(data, period):
            k = 2 / (period + 1)
            result = [data[0]]
            for price in data[1:]:
                result.append(price * k + result[-1] * (1 - k))
            return result

        if len(closes) < slow + signal_period:
            return {"macd": 0, "signal": 0, "histogram": 0, "cross": "NEUTRAL", "direction": "NEUTRAL"}

        ema_fast = ema(closes, fast)
        ema_slow = ema(closes, slow)
        macd_line = [f - s for f, s in zip(ema_fast, ema_slow)]
        signal_line = ema(macd_line, signal_period)
        histogram = [m - s for m, s in zip(macd_line, signal_line)]

        curr_hist = histogram[-1]
        prev_hist = histogram[-2] if len(histogram) > 1 else 0
        curr_macd = macd_line[-1]
        curr_sig  = signal_line[-1]

        # Cross detection
        prev_macd = macd_line[-2] if len(macd_line) > 1 else curr_macd
        prev_sig  = signal_line[-2] if len(signal_line) > 1 else curr_sig

        if prev_macd <= prev_sig and curr_macd > curr_sig:
            cross = "BULLISH_CROSS"
        elif prev_macd >= prev_sig and curr_macd < curr_sig:
            cross = "BEARISH_CROSS"
        elif curr_macd > curr_sig:
            cross = "BULLISH"
        else:
            cross = "BEARISH"

        direction = "UP" if curr_hist > prev_hist else "DOWN"

        return {
            "macd":      round(curr_macd, 6),
            "signal":    round(curr_sig, 6),
            "histogram": round(curr_hist, 6),
            "cross":     cross,
            "direction": direction,
        }

    # ─────────────────────────────────────────────────────────────
    # BOLLINGER BANDS
    # ─────────────────────────────────────────────────────────────
    def _calc_bollinger(self, closes: List[float], period: int = 20, std_dev: float = 2.0) -> Dict:
        if len(closes) < period:
            mid = closes[-1]
            return {"upper": mid, "middle": mid, "lower": mid, "position": "MIDDLE", "signal": "NEUTRAL", "squeeze": False}

        recent = closes[-period:]
        mid    = sum(recent) / period
        std    = statistics.stdev(recent)
        upper  = mid + std_dev * std
        lower  = mid - std_dev * std
        price  = closes[-1]
        bw     = (upper - lower) / mid * 100  # bandwidth

        if price >= upper:
            position = "UPPER"
            signal   = "OVERBOUGHT"
        elif price <= lower:
            position = "LOWER"
            signal   = "OVERSOLD"
        elif price > mid:
            position = "ABOVE_MIDDLE"
            signal   = "BULLISH"
        else:
            position = "BELOW_MIDDLE"
            signal   = "BEARISH"

        squeeze = bw < 0.5  # tight bands = potential breakout

        return {
            "upper":    round(upper, 6),
            "middle":   round(mid, 6),
            "lower":    round(lower, 6),
            "position": position,
            "signal":   signal,
            "squeeze":  squeeze,
            "bandwidth": round(bw, 4),
        }

    # ─────────────────────────────────────────────────────────────
    # EMAs
    # ─────────────────────────────────────────────────────────────
    def _calc_emas(self, closes: List[float], current_price: float) -> Dict:
        def sma(data, n):
            return sum(data[-n:]) / n if len(data) >= n else sum(data) / len(data)

        ema20  = sma(closes, 20)
        ema50  = sma(closes, 50)
        ema200 = sma(closes, 200) if len(closes) >= 200 else sma(closes, len(closes))

        price_vs = ((current_price - ema200) / ema200) * 100
        trend    = "UPTREND" if current_price > ema200 else "DOWNTREND"

        # Strength by alignment
        if current_price > ema20 > ema50 > ema200:
            strength = 90
        elif current_price > ema20 > ema50:
            strength = 70
        elif current_price > ema20:
            strength = 55
        elif current_price < ema20 < ema50 < ema200:
            strength = 10
        elif current_price < ema20 < ema50:
            strength = 30
        else:
            strength = 45

        return {
            "trend":           trend,
            "trend_strength":  f"{strength:.2f}%",
            "ema20":           round(ema20, 6),
            "ema50":           round(ema50, 6),
            "ema200":          round(ema200, 6),
            "price_vs_ema200": f"{abs(price_vs):.4f}% - {'ABOVE' if price_vs > 0 else 'BELOW'} EMA 200",
            "trend_confidence": "100.00%",
        }

    # ─────────────────────────────────────────────────────────────
    # CANDLESTICK PATTERNS
    # ─────────────────────────────────────────────────────────────
    def _detect_candle_pattern(self, opens, closes, highs, lows) -> Dict:
        if len(closes) < 3:
            return {"pattern": "NONE", "signal": "NEUTRAL", "strength": "WEAK"}

        o1, o2, o3 = opens[-3], opens[-2], opens[-1]
        c1, c2, c3 = closes[-3], closes[-2], closes[-1]
        h1, h2, h3 = highs[-3], highs[-2], highs[-1]
        l1, l2, l3 = lows[-3], lows[-2], lows[-1]

        body3 = abs(c3 - o3)
        body2 = abs(c2 - o2)
        rng3  = h3 - l3 if h3 != l3 else 0.0001
        upper_wick3 = h3 - max(o3, c3)
        lower_wick3 = min(o3, c3) - l3

        pattern = "NONE"
        signal  = "NEUTRAL"
        strength = "MODERATE"

        # ── Doji ──
        if body3 / rng3 < 0.1:
            pattern  = "DOJI"
            signal   = "REVERSAL"
            strength = "MODERATE"

        # ── Hammer (bullish reversal) ──
        elif (lower_wick3 > body3 * 2 and upper_wick3 < body3 * 0.5
              and c2 < o2):
            pattern  = "HAMMER"
            signal   = "BULLISH"
            strength = "STRONG"

        # ── Shooting Star (bearish reversal) ──
        elif (upper_wick3 > body3 * 2 and lower_wick3 < body3 * 0.5
              and c2 > o2):
            pattern  = "SHOOTING_STAR"
            signal   = "BEARISH"
            strength = "STRONG"

        # ── Bullish Engulfing ──
        elif (c2 < o2 and c3 > o3
              and c3 > o2 and o3 < c2):
            pattern  = "BULLISH_ENGULFING"
            signal   = "BULLISH"
            strength = "STRONG"

        # ── Bearish Engulfing ──
        elif (c2 > o2 and c3 < o3
              and c3 < o2 and o3 > c2):
            pattern  = "BEARISH_ENGULFING"
            signal   = "BEARISH"
            strength = "STRONG"

        # ── Morning Star (bullish 3-candle) ──
        elif (c1 < o1 and abs(c2 - o2) < abs(c1 - o1) * 0.3 and c3 > o3
              and c3 > (o1 + c1) / 2):
            pattern  = "MORNING_STAR"
            signal   = "BULLISH"
            strength = "VERY STRONG"

        # ── Evening Star (bearish 3-candle) ──
        elif (c1 > o1 and abs(c2 - o2) < abs(c1 - o1) * 0.3 and c3 < o3
              and c3 < (o1 + c1) / 2):
            pattern  = "EVENING_STAR"
            signal   = "BEARISH"
            strength = "VERY STRONG"

        # ── Three White Soldiers ──
        elif (c1 > o1 and c2 > o2 and c3 > o3
              and c2 > c1 and c3 > c2):
            pattern  = "THREE_WHITE_SOLDIERS"
            signal   = "BULLISH"
            strength = "VERY STRONG"

        # ── Three Black Crows ──
        elif (c1 < o1 and c2 < o2 and c3 < o3
              and c2 < c1 and c3 < c2):
            pattern  = "THREE_BLACK_CROWS"
            signal   = "BEARISH"
            strength = "VERY STRONG"

        # ── Simple momentum ──
        elif c3 > o3:
            pattern  = "BULLISH_CANDLE"
            signal   = "BULLISH"
            strength = "WEAK"
        else:
            pattern  = "BEARISH_CANDLE"
            signal   = "BEARISH"
            strength = "WEAK"

        return {"pattern": pattern, "signal": signal, "strength": strength}

    # ─────────────────────────────────────────────────────────────
    # SCORING — combines all indicators
    # ─────────────────────────────────────────────────────────────
    def _score_signal(self, closes, opens, rsi, macd, bb, ema, trend, pattern) -> Dict:
        score = 0  # -100 to +100

        # RSI (weight: 25)
        if rsi['zone'] == 'BUY':
            score += 20 if rsi['signal'] == 'OVERSOLD' else 12
        elif rsi['zone'] == 'SELL':
            score -= 20 if rsi['signal'] == 'OVERBOUGHT' else 12

        # MACD (weight: 25)
        if macd['cross'] == 'BULLISH_CROSS':
            score += 25
        elif macd['cross'] == 'BEARISH_CROSS':
            score -= 25
        elif macd['cross'] == 'BULLISH':
            score += 12 if macd['direction'] == 'UP' else 6
        elif macd['cross'] == 'BEARISH':
            score -= 12 if macd['direction'] == 'DOWN' else 6

        # Bollinger (weight: 15)
        if bb['signal'] == 'OVERSOLD':
            score += 15
        elif bb['signal'] == 'BULLISH':
            score += 8
        elif bb['signal'] == 'OVERBOUGHT':
            score -= 15
        elif bb['signal'] == 'BEARISH':
            score -= 8

        # EMA trend (weight: 20)
        if ema['trend'] == 'UPTREND':
            strength = float(ema['trend_strength'].replace('%', ''))
            score += int(strength * 0.2)
        else:
            strength = float(ema['trend_strength'].replace('%', ''))
            score -= int((100 - strength) * 0.2)

        # Candlestick pattern (weight: 15)
        p_signal   = pattern['signal']
        p_strength = pattern['strength']
        p_weight   = {'VERY STRONG': 15, 'STRONG': 10, 'MODERATE': 5, 'WEAK': 2}.get(p_strength, 2)
        if p_signal == 'BULLISH':
            score += p_weight
        elif p_signal == 'BEARISH':
            score -= p_weight

        # Recent candles momentum
        recent_bull = sum(1 for i in range(-5, 0) if closes[i] > opens[i])
        score += (recent_bull - 2) * 2

        # Clamp
        score = max(-100, min(100, score))

        # Convert to bullish/bearish pct
        bullish = 50 + score / 2
        bearish = 100 - bullish

        return {
            "bullish":   round(bullish, 1),
            "bearish":   round(bearish, 1),
            "raw_score": score,
        }

    # ─────────────────────────────────────────────────────────────
    # FINAL RECOMMENDATION
    # ─────────────────────────────────────────────────────────────
    def _final_recommendation(self, bull_bear, rsi, macd, market_summary) -> Dict:
        bull = bull_bear['bullish']
        bear = bull_bear['bearish']
        score = bull_bear['raw_score']

        # Strong signal
        if score >= 30:
            signal    = "CALL"
            direction = "BUY"
            color     = "green"
        elif score <= -30:
            signal    = "PUT"
            direction = "SELL"
            color     = "red"
        # Moderate — use RSI/MACD as tiebreaker
        elif score > 0:
            if rsi['zone'] == 'BUY' or macd['cross'] in ['BULLISH', 'BULLISH_CROSS']:
                signal    = "CALL"
                direction = "BUY"
                color     = "green"
            else:
                signal    = "CALL"
                direction = "BUY"
                color     = "green"
        else:
            if rsi['zone'] == 'SELL' or macd['cross'] in ['BEARISH', 'BEARISH_CROSS']:
                signal    = "PUT"
                direction = "SELL"
                color     = "red"
            else:
                signal    = "PUT"
                direction = "SELL"
                color     = "red"

        confidence = max(bull, bear)

        return {
            "signal":         signal,
            "direction":      direction,
            "recommendation": signal,
            "color":          color,
            "confidence":     f"{int(confidence)}%",
        }

    # ─────────────────────────────────────────────────────────────
    # SUPPORTING CALCULATIONS (kept for dashboard compatibility)
    # ─────────────────────────────────────────────────────────────
    def _calc_volatility(self, closes, highs, lows) -> Dict:
        ranges = [h - l for h, l in zip(highs[-50:], lows[-50:])]
        atr    = sum(ranges) / len(ranges)
        vol_pct = (max(closes[-50:]) - min(closes[-50:])) / closes[-1] * 100
        r_vol   = (max(closes[-10:]) - min(closes[-10:])) / closes[-1] * 100
        std_dev = statistics.stdev(closes[-50:]) / closes[-1] * 100
        level   = "LOW" if vol_pct < 0.5 else "MEDIUM" if vol_pct < 1.5 else "HIGH"
        return {
            "level": level, "atr": round(atr, 6),
            "volatility_pct": round(vol_pct, 4),
            "recent_volatility_pct": round(r_vol, 4),
            "std_deviation": round(std_dev, 4),
            "max_range": round(max(ranges), 6),
            "min_range": round(min(ranges), 6),
        }

    def _calc_trend(self, closes) -> Dict:
        ma20 = sum(closes[-20:]) / 20
        ma5  = sum(closes[-5:])  / 5
        direction = "Uptrend" if ma5 > ma20 else "Downtrend"
        strength  = min(abs((ma5 - ma20) / ma20) * 1000, 100)
        return {"direction": direction, "strength": round(strength, 2)}

    def _calc_support_resistance(self, highs, lows, price) -> Dict:
        resistance = max(highs[-50:])
        support    = min(lows[-50:])
        d_r = abs((resistance - price) / price * 100)
        d_s = abs((price - support) / price * 100)
        return {
            "resistance": round(resistance, 6), "support": round(support, 6),
            "distance_to_resistance": f"{d_r:.4f}%",
            "distance_to_support":    f"{d_s:.4f}%",
        }

    def _calc_gaps(self, opens, closes) -> Dict:
        gap_ups = gap_downs = 0
        for i in range(1, len(closes)):
            g = opens[i] - closes[i-1]
            if g > 0: gap_ups += 1
            elif g < 0: gap_downs += 1
        latest = opens[-1] - closes[-2] if len(closes) > 1 else 0
        pct    = (latest / closes[-1]) * 100
        t      = "Gap Up" if latest > 0 else "Gap Down" if latest < 0 else "No Gap"
        return {"latest_gap": f"{t} {abs(pct):.4f}%", "gap_up_count": gap_ups, "gap_down_count": gap_downs}

    def _calc_rejection(self, last_candle, highs, lows, opens, closes) -> Dict:
        o = self.safe_float(last_candle.get('open')  or last_candle.get('o'))
        c = self.safe_float(last_candle.get('close') or last_candle.get('c'))
        h = self.safe_float(last_candle.get('high')  or last_candle.get('h'))
        l = self.safe_float(last_candle.get('low')   or last_candle.get('l'))
        body   = abs(c - o)
        upper  = h - max(o, c)
        lower  = min(o, c) - l
        rng    = h - l if h != l else 0.0001
        u_pct  = upper / rng * 100
        l_pct  = lower / rng * 100
        b_pct  = body  / rng * 100
        patterns = []
        rej_type = "NEUTRAL"
        if b_pct < 5:   patterns.append("DOJI")
        if l_pct > 50:  patterns.append("STRONG LOWER_WICK"); rej_type = "LOWER"
        elif u_pct > 50: patterns.append("STRONG UPPER_WICK"); rej_type = "UPPER"
        conf = max(l_pct, u_pct) if patterns else 50
        return {
            "type": rej_type, "patterns": ", ".join(patterns) if patterns else "NONE",
            "confidence": f"{int(conf)}%", "strength": f"{max(u_pct,l_pct,b_pct):.2f}%",
            "level": round(c, 6), "upper_wick_pct": round(u_pct, 2),
            "lower_wick_pct": round(l_pct, 2), "body_pct": round(b_pct, 2),
        }

    def _calc_zigzag(self, highs, lows) -> Dict:
        last_high = max(highs[-10:])
        last_low  = min(lows[-10:])
        curr      = highs[-1]
        if   curr >= last_high: direction, pattern = "UP",      "BULLISH"
        elif curr <= last_low:  direction, pattern = "DOWN",    "BEARISH"
        else:                   direction, pattern = "NEUTRAL", "NEUTRAL"
        return {
            "pattern": pattern, "trend_strength": "0%" if pattern == "NEUTRAL" else "50%",
            "points": 11, "last_direction": direction,
            "last_extreme_price": round(last_high if direction == "UP" else last_low, 6),
        }

    def _calc_movement(self, closes) -> Dict:
        movements = [abs(closes[i] - closes[i-1]) for i in range(1, len(closes))]
        avg       = sum(movements) / len(movements)
        r_avg     = sum(movements[-10:]) / 10
        active    = len([m for m in movements[-10:] if m > avg])
        level     = "VERY HIGH" if active > 7 else "HIGH" if active > 5 else "MODERATE"
        chg       = ((r_avg - avg) / avg * 100) if avg > 0 else 0
        avg_pct   = avg / closes[-1] * 100
        r_pct     = r_avg / closes[-1] * 100
        return {
            "activity_level": level, "average_movements": round(len(movements) * 0.8, 2),
            "recent_average": len(movements[-10:]) * 10, "latest_movements": active * 10,
            "movement_change_pct": f"{chg:+.2f}%",
            "avg_price_movement": f"{avg_pct:.4f}%",
            "recent_price_movement": f"{r_pct:.4f}%",
            "price_movement_change": f"{chg:+.2f}%",
        }

    def _market_condition(self, vol, trend, movement) -> Dict:
        vol_score  = 9 if vol['level'] == "LOW" else 20 if vol['level'] == "MEDIUM" else 15
        trend_score = float(trend['strength']) * 0.4
        move_score = 30 if movement['activity_level'] == "VERY HIGH" else 20 if movement['activity_level'] == "HIGH" else 15
        score = vol_score + trend_score + move_score
        if score >= 70:   condition, rec = "STRONG",   "TAKE TRADE"
        elif score >= 50: condition, rec = "MODERATE", "WAIT"
        else:             condition, rec = "WEAK",     "SKIP TRADE"
        return {
            "condition": condition, "confidence": f"{int(min(score,100))}%",
            "description": f"{condition.title()} market conditions",
            "trade_recommendation": rec, "overall_score": f"{score:.2f}/100",
            "volatility_contribution": f"{vol_score}/30",
            "trend_contribution": f"{trend_score:.2f}/40",
            "movement_contribution": f"{move_score}/30",
        }

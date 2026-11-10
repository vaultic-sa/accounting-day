# تحدّي اليوم العالمي للمحاسبة

لعبة محاسبية من ست جولات، بلوحة متصدرين مشتركة بين جميع اللاعبين.

- الواجهة: ملف واحد `index.html` (HTML + CSS + JavaScript)، منشور على GitHub Pages.
- قاعدة البيانات: Supabase (Postgres).

## كيف تعمل لوحة المتصدرين

| الخطوة | ما يحدث |
|---|---|
| كتابة الاسم | `register_player` ينشئ لاعبًا برقم فريد متسلسل ورمز سري يُحفظ على الجهاز (تُخزَّن بصمته SHA-256 فقط في القاعدة) |
| «ادخل اللعبة» | `start_game` يفتح جلسة لعب، وتبدأ ساعة الخادم |
| نهاية اللعبة | `finish_game` يستقبل الإجابات، ويعيد **الخادم** حساب النقاط بقواعد اللعبة ومفتاح الإجابات المخزّن في القاعدة. تُسجَّل الجلسة مرة واحدة فقط، وأي تكرار يعيد النتيجة نفسها |
| الترتيب | `get_leaderboard` يرتّب أفضل نتيجة لكل لاعب: النقاط ↓ ثم مدة اللعب ↑ (بساعة الخادم) ثم الأسبق إنهاءً |

الجداول مغلقة بالكامل (RLS مفعّل دون سياسات، وكل الصلاحيات مسحوبة من `anon`)، والوصول الوحيد عبر الدوال الأربع.
الواجهة تحمل المفتاح العام (anon / publishable) فقط، ولا يُستخدم مفتاح `service_role` في أي مكان.

### الحماية

- حدّ للطلبات لكل عنوان IP (بعنوان Cloudflare الذي لا يمكن تزويره): 300 تسجيل و600 بدء لعبة كل 10 دقائق، و30 لعبة في الساعة لكل لاعب.
- لا تُقبل لعبة تنتهي في أقل من 60 ثانية، أو بوقت متبقٍ يتجاوز وقت السؤال، أو بأكثر من 3 تلميحات، أو بإجابات ناقصة أو مكررة.
- التسجيل في Supabase Auth مغلق (اللعبة لا تستخدم حسابات).
- حد معروف: الأسئلة وإجاباتها داخل الصفحة لأن اللعبة تعرض التصحيح فورًا، فلا يمكن منع من يقرأ الكود من الإجابة الكاملة؛ لكن لا يمكن تجاوز أعلى نتيجة ممكنة (7,370) ولا تعديل نتيجة ولا تكرارها.

### الإشراف (من SQL Editor)

```sql
-- إخفاء لاعب من الترتيب (اسم مسيء أو نتيجة مشبوهة) دون حذف بياناته
update public.players set hidden = true  where player_no = 17;
-- إعادة إظهاره
update public.players set hidden = false where player_no = 17;
-- عرض أحدث المشاركين
select p.player_no, p.name, s.score, s.duration_ms, s.finished_at
from public.game_sessions s join public.players p on p.id = s.player_id
where s.status = 'finished' order by s.finished_at desc limit 50;
```

## الإعداد

1. نفّذ في Supabase → SQL Editor بالترتيب:
   - `supabase/001_leaderboard.sql`
   - `supabase/answer_key.sql`
   - `supabase/002_hardening.sql`
2. ضع في `index.html` قيمتي `SUPABASE_URL` و `SUPABASE_ANON_KEY` (من Project Settings → API).

إذا عدّلت الأسئلة في `index.html` فأعد توليد مفتاح الإجابات:

```bash
node scripts/extract-key.mjs > supabase/answer_key.sql
```

ثم نفّذ الملف الناتج في SQL Editor.

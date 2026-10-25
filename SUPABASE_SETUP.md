# ချုပ်ချယ် App ကို Supabase နှင့် ချိတ်ဆက်ရန်

ဒီ project က Supabase ကို ချိတ်နိုင်အောင် ပြင်ထားသည်။ `SUPABASE_URL` နှင့် server-side secret key ကို သတ်မှတ်ထားလျှင် စာရင်း၊ ဈေးမှတ်တမ်း၊ ဖျက်ထားသည့် ID နှင့် login စနစ်ကို Supabase သုံးမည်။ မသတ်မှတ်ထားလျှင် local server က `private-data/` JSON ဖိုင်ကို ဆက်သုံးမည်။ Cloudflare Worker တွင် Supabase setting မရှိပါက login/data API ကို မဖွင့်ပါ။

## ၁။ Supabase Project ဖန်တီးရန်

Supabase Dashboard တွင် Project အသစ်ဖန်တီးပါ။ Project ဖွင့်ပြီးနောက် **Integrations → Data API** မှ Project URL ကိုယူပါ။ **Settings → API Keys** မှ server-only **Secret key** (`sb_secret_...`) ကို ဖန်တီးပါ။ Legacy project တွင် `service_role` key သာရှိပါက အဲဒါကို server secret အဖြစ်သုံးနိုင်သည်။

## ၂။ Database ဇယားများဖန်တီးရန်

Project ထဲရှိ **SQL Editor** ကိုဖွင့်ပြီး ဒီ folder ထဲက `supabase.sql` ဖိုင်အကြောင်းအရာအားလုံးကို paste လုပ်ကာ Run နှိပ်ပါ။ ဇယားတွေမှာ RLS ဖွင့်ထားပြီး `anon` နဲ့ `authenticated` role များကို တိုက်ရိုက်ဖတ်/ရေးခွင့် မပေးထားပါ။ App က server-side secret ဖြင့်သာ ချိတ်သည်။

## ၃။ Cloudflare Worker တွင် ထည့်ရန်

Worker ၏ **Settings → Variables and Secrets** ထဲတွင် အောက်ပါတန်ဖိုးများ သတ်မှတ်ပါ။

- `SUPABASE_URL` — Supabase Project URL (ပုံမှန် variable အဖြစ်ရသည်)
- `SUPABASE_SECRET_KEY` — Supabase `sb_secret_...` key (Secret အဖြစ်သိမ်းရန်)
- `FABRIC_LOGIN_CODE` — မျှဝေသုံးမည့် app login code (Secret အဖြစ်သိမ်းရန်)

ပြီးလျှင် Worker ကို redeploy လုပ်ပါ။ **Secret key ကို GitHub ဖိုင်၊ frontend သို့မဟုတ် chat ထဲ မထည့်ပါနှင့်။** GitHub မှာ code ဖိုင်များသာထားပါ။

## ၄။ Local server ဖြင့် စမ်းရန်

`server.py` ရှိ folder ထဲတွင် `.env.example` ကို `.env` အဖြစ် copy လုပ်ပြီး Supabase Project URL, secret key, login code ကို ဖြည့်ပါ။ ထို့နောက် `Start-App.bat` ကိုဖွင့်ပါ။ `.env` ကို `.gitignore` က GitHub တင်ခြင်းမှ ဖယ်ထားသည်။

## အရေးကြီးသော မှတ်ချက်

- Supabase ထဲရှိ data သည် `app_items`, `app_history`, `app_deleted_ids` ဇယားများတွင် သိမ်းမည်။ Login code ၏ hash နှင့် session-signing key ကို `app_settings` တွင် သိမ်းမည်။
- Worker ကို ပထမဆုံးဖွင့်သည့်အခါ `FABRIC_LOGIN_CODE` ဖြင့် login setting ကိုတစ်ကြိမ်တည်ဆောက်မည်။ နောက်ပိုင်း login code ကို App ထဲက **Change Login Code** ဖြင့်ပြောင်းနိုင်သည်။
- လက်ရှိ local စာရင်းကို Supabase သို့ ရွှေ့မည်ဆိုလျှင် ပထမဆုံး login ဝင်သည့် browser ထဲမှာ ရှိပြီးသား local data ကို Supabase က ဗလာဖြစ်နေချိန်တွင် upload လုပ်မည်။ မူရင်း JSON/data ဖိုင်ကို backup အဖြစ် မဖျက်ပါနှင့်။
- Secret key ပါသော request အားလုံးကို server/Worker ကသာ ပို့သည်။ Browser ထဲရှိ JavaScript မှ Supabase secret key ကို မသုံးပါ။

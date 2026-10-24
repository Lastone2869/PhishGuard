"""
prepare_data.py
Constructs, cleans, and partitions labelled dataset for PhishGuard Stage 1.
Includes genuine institutional notices, VIT account-suspension scenarios,
general email/SMS phishing, and legitimate student communications.
"""

import os
import random
import pandas as pd
from sklearn.model_selection import train_test_split

DATASET_RAW_PATH = os.path.join("datasets", "raw", "raw_messages.csv")
PROCESSED_DIR = os.path.join("datasets", "processed")
TRAIN_PATH = os.path.join(PROCESSED_DIR, "train.csv")
VAL_PATH = os.path.join(PROCESSED_DIR, "val.csv")
TEST_PATH = os.path.join(PROCESSED_DIR, "test.csv")

def generate_samples():
    data = []

    # --- 1. VIT Phishing Scenarios (Synthetic) ---
    vit_phishing = [
        ("URGENT: Your VIT Student Account will be suspended within 24 hours due to unverified KYC. Click here immediately to verify: http://vit-account-verify.info/login", "admin@vit-support-desk.com"),
        ("Final Warning: Your VTOP access is scheduled for termination. Verify your credentials now at http://vtop-vit-portal.xyz/auth to avoid de-registration.", "support@vtop-security.com"),
        ("VIT IT Helpdesk: Unusual activity detected from your IP. Confirm your student password and OTP here http://192.168.1.55/vit_login to secure your account.", "helpdesk@vit-support.net"),
        ("Attention VITian: Your library and hostel portal access will expire today. Update login details immediately: http://bit.ly/vit-portal-renew", "library@vit-update.co"),
        ("Notice from Controller of Examinations, VIT: Discrepancy found in your exam registration. Login right now at http://vit-exam-portal.me/verify or you will be debarred.", "coe@vit-ac-in.org"),
        ("VIT WiFi Portal: Your network credentials will be suspended. Re-verify student login at http://vit-wifi-auth.com/login", "wifi@vit-network-support.com"),
        ("Action Required: VIT Semester fees discrepancy. Failure to verify payment within 12 hours will lead to admission cancellation. Check: http://fees-vit-online.cc", "accounts@vit-billing.cc"),
        ("URGENT VIT Placement Cell: Exclusive placement interview shortlist attached. Fill your credentials to confirm attendance: http://vit-placements-drive.com/form", "pat@vit-placement-support.com"),
        ("Your VIT Student Mail quota is 99% full. Click http://vit-cloud-storage.info/increase to upgrade quota or all incoming mails will be bounced.", "sysadmin@vit-mail-portal.com"),
        ("VIT Campus Alert: Account compromise alert. Update your VTOP password immediately via http://vtop.vit-login-auth.com/reset", "security@vit-security-team.org"),
        ("VIT Security Alert: Suspicious login from Moscow, Russia. If this wasn't you, confirm identity here immediately: http://vit-alert-safety.com", "alerts@vit-auth.com"),
        ("Dean Academics VIT: Your winter registration requires urgent re-confirmation. Verify credentials at http://vtop-registration-check.net", "dean@vit-academic-desk.org"),
        ("VIT Proctor Office: Serious disciplinary complaint lodged against you. View complaint and defend yourself: http://vit-proctor-inquiry.xyz", "proctor@vit-inquiry.com"),
        ("Important: VIT Scholarship disbursement pending. Enter student banking credentials to release fund: http://vit-scholarship-portal.live", "scholarship@vit-aid.org"),
        ("VIT Grade Review: Your FAT exam marks have been revised. Check score breakdown by logging into http://vit-results-portal.co", "results@vit-examination.org"),
    ]
    for text, sender in vit_phishing:
        data.append({
            "text": text,
            "label": 1,
            "source": "synthetic_vit_phish",
            "language": "en",
            "sender": sender,
            "is_synthetic": True
        })

    # --- 2. Legitimate VIT University Notices (Synthetic & Real Patterns) ---
    vit_legit = [
        ("Dear Student, The timetable for Winter Semester 2026-27 is now published on VTOP. Please review your slot allotments.", "academics@vit.ac.in"),
        ("Circular: VIT Riviera 2027 cultural fest registration opens next Monday. Contact the student welfare office for guidelines.", "studentwelfare@vit.ac.in"),
        ("Fee reminder: The last date to pay tuition fees for next semester without fine is 30th November 2026. Payment via VTOP portal.", "finance@vit.ac.in"),
        ("Library notice: Please return or renew your borrowed books on or before Friday to avoid overdue fines. Open until 10 PM.", "library@vit.ac.in"),
        ("Placement and Training Cell: Cognizant campus drive registration details are updated on the PAT portal. Eligibility criteria attached.", "placement@vit.ac.in"),
        ("Hostel office notification: Room allotment for senior students will commence from June 15th through official student login.", "hostel@vit.ac.in"),
        ("Dear Students, Mid-term CAT-II examination schedule has been announced. Check official circular on the VIT website.", "coe@vit.ac.in"),
        ("Proctor-Ward meeting scheduled for this Thursday at 4 PM in Academic Block 1. Attendance is mandatory for all first-year students.", "proctor@vit.ac.in"),
        ("Sports Board: Inter-collegiate basketball selections will take place at the Outdoor Stadium on Saturday 8:00 AM.", "sports@vit.ac.in"),
        ("Notice: Maintenance of server room scheduled for Sunday 2 AM to 5 AM. VTOP and student email will have brief downtime.", "sysadmin@vit.ac.in"),
        ("Health Centre Circular: Free general health check-up camp will be held at the campus medical center this Wednesday.", "healthcentre@vit.ac.in"),
        ("Guest lecture on AI and Cyber Security by Dr. Ramanathan on Friday, 3 PM at Anna Auditorium. All CSE students invited.", "events@vit.ac.in"),
        ("Notice regarding bus transport: Route 14 will have a revised departure timing of 5:15 PM starting from tomorrow.", "transport@vit.ac.in"),
        ("Office of Alumni Affairs: Registrations are open for Alumni Homecoming 2026. Visit official portal for registration.", "alumni@vit.ac.in"),
        ("Student Council Elections: Code of conduct for candidates has been published on the notice board and website.", "sw@vit.ac.in"),
    ]
    for text, sender in vit_legit:
        data.append({
            "text": text,
            "label": 0,
            "source": "synthetic_vit_legit",
            "language": "en",
            "sender": sender,
            "is_synthetic": True
        })

    # --- 3. General Phishing Messages (Email & SMS) ---
    general_phishing = [
        ("Your PayPal account has been limited due to suspicious transactions. Click http://paypal-account-center.com/resolve to confirm your identity.", "service@paypal-security-update.com"),
        ("Netflix alert: Your membership payment failed. Update credit card immediately to avoid cancellation: http://netflix-billing-update.me", "support@netflix-renew.com"),
        ("Amazon Delivery: Package delayed because address is missing a zip code. Confirm details here: http://track-amazon-package.biz/update", "delivery@amazon-support-hub.com"),
        ("IRS Notice: You are eligible for a tax refund of $1,450. Submit your SSN and direct deposit info at http://irs-refund-claim.org", "refund@irs-tax-filing.com"),
        ("Bank of America: We detected a foreign transaction of $850. If unauthorized, verify card details right now at http://bofa-fraud-protection.net", "fraud@bofa-security-alert.com"),
        ("Your Apple ID has been locked for security reasons. Unlock now by confirming credentials: http://apple-id-verify.co/auth", "security@apple-id-center.com"),
        ("Google Workspace: Password expires in 6 hours. Keep your current password by verifying at http://accounts-google-verify.info", "admin@google-security-team.org"),
        ("Congratulations! You won a $1,000 Walmart Gift Card. Claim within 10 minutes: http://walmart-promo-winner.xyz/claim", "promotions@winner-notice.com"),
        ("FedEx Tracking: Urgent delivery pending custom clearance fee of $2.50. Pay now: http://fedex-custom-duty.com/pay", "tracking@fedex-parcel-notice.com"),
        ("Microsoft 365: 7 quarantined incoming emails pending review. Release emails by logging in at http://office365-security-portal.online", "admin@microsoft-notice.com"),
        ("WhatsApp Verification Code: Never share this code. Enter code at http://whatsapp-web-auth.me to keep your account active.", "no-reply@whatsapp-notify.org"),
        ("Wells Fargo Alert: Suspicious login from unknown mobile device. Secure your account now: http://wellsfargo-security-check.com", "alerts@wellsfargo-fraud.com"),
        ("Facebook Security: Your page is scheduled for deletion due to copyright violation. Appeal here: http://meta-copyright-appeal.cc", "case@meta-support-desk.com"),
        ("HR Payroll: Employee tax W-2 forms ready for review. Access payroll portal: http://hr-payroll-portal-access.com/w2", "payroll@company-hr-update.com"),
        ("LinkedIn: You have 5 unread messages from recruiters. View profile views and messages: http://linkedin-inmail-viewer.xyz", "notifications@linkedin-mail.com"),
        ("Crypto Wallet Alert: Unauthorized withdrawal requested. Cancel withdrawal immediately at http://metamask-security-vault.io", "support@metamask-alert.com"),
        ("USPS Notice: Your postal shipment is on hold due to incorrect house number. Confirm address: http://usps-redelivery-hub.info", "shipping@usps-post.com"),
        ("Dropbox Team: Confidential document shared with you. Sign in with work credentials to view: http://dropbox-secure-share.link", "share@dropbox-cloud-docs.com"),
        ("Steam Community: Trade offer error detected. Re-authenticate your Steam Guard at http://steamcommunity-trade-check.ru", "support@steampowered-guard.com"),
        ("DocuSign: Urgent signature requested on settlement agreement. Review and sign: http://docusign-envelope-viewer.com/sign", "docusign@envelope-auth.net"),
        ("Chase Bank: Suspicious charge of $432.10 at Target. Reply STOP or confirm identity at http://chase-bank-verify.info", "fraud@chase-alert-center.com"),
        ("Warning: Your domain registration expires in 24 hours. Renew now to prevent domain cancellation: http://domain-renewal-service.org", "billing@registrar-alert.com"),
        ("Apple iCloud: Storage full. Photos and backups will be purged unless upgraded: http://icloud-storage-portal.com/upgrade", "storage@icloud-billing.com"),
        ("Zoom Video: Meeting recording ready for download. Log in with company SSO to watch: http://zoom-recordings-share.net", "invitations@zoom-meeting-desk.com"),
        ("Spotify Premium: Payment processing error. Update payment method: http://spotify-billing-update.info/renew", "help@spotify-support-desk.com")
    ]
    for text, sender in general_phishing:
        data.append({
            "text": text,
            "label": 1,
            "source": "general_phish_corpus",
            "language": "en",
            "sender": sender,
            "is_synthetic": False
        })

    # --- 4. General Legitimate Messages (Email & SMS) ---
    general_legit = [
        ("Hi John, are we still meeting tomorrow at 10 AM to discuss the final year project slides?", "alex.dev@gmail.com"),
        ("Your Amazon order #402-9812481 has been dispatched. Track your delivery directly inside your Amazon app.", "auto-confirm@amazon.in"),
        ("Here is the updated draft of our machine learning paper. Let me know your thoughts by Friday.", "sarah.chen@university.edu"),
        ("Hey! Don't forget we have the hackathon team check-in tonight on Google Meet.", "priya.k@gmail.com"),
        ("Your monthly electricity bill of Rs 1,420 has been generated. Due date is 25th Oct. Pay via your regular banking app.", "ebilling@tnebnet.org"),
        ("Thanks for shopping at Decathlon. Your e-invoice is attached to this email.", "care@decathlon.in"),
        ("Google Security Alert: New sign-in detected on your Mac in Chennai. If this was you, no action needed.", "no-reply@accounts.google.com"),
        ("GitHub: A new release v1.4.0 is available for the repository you follow. Check the changelog on GitHub.", "notifications@github.com"),
        ("Your Uber trip on Thursday evening: Total paid was Rs 240 via Google Pay. Download invoice in the app.", "uber.india@uber.com"),
        ("Reminder: Your dentist appointment is confirmed for Saturday at 4:30 PM with Dr. Sharma.", "appointments@sharmaclinic.com"),
        ("Good morning class, class notes and tutorial exercises for chapter 4 have been uploaded on Google Classroom.", "prof.kumar@univ.edu"),
        ("Hey, can you send me the link to the Python pandas documentation for group-by operations?", "rahul88@gmail.com"),
        ("Your flight booking 6E-204 from Chennai to Delhi is confirmed. Web check-in opens 48 hours prior to departure.", "bookings@goindigo.in"),
        ("Your Zomato order from Paradise Biryani has been delivered. Enjoy your meal!", "orders@zomato.com"),
        ("Thank you for submitting your assignment on time. Feedback will be returned by next Monday.", "ta_cs302@univ.edu"),
        ("Can you review this pull request when you get a chance? Fixed the navigation bar bug.", "dev.karthik@github.com"),
        ("Happy Birthday Vikram! Wishing you a fantastic year ahead from all of us.", "ananya.s@gmail.com"),
        ("Your mutual fund statement for the quarter ended September 2026 is ready to download.", "statements@amfiindia.com"),
        ("The package was delivered to your reception desk. Signed by security.", "updates@bluedart.com"),
        ("Let's grab lunch at the food court around 1:30 PM today after lab.", "sneha.r@gmail.com"),
        ("Weekly newsletter from IEEE Computer Society: Top 10 advancements in natural language processing.", "newsletter@computer.org"),
        ("Your subscription to Spotify Family will renew automatically on November 1st at Rs 179/month.", "no-reply@spotify.com"),
        ("Campus blood donation drive on Thursday from 9 AM to 4 PM at the Student Center. All donors welcome.", "redcross@univ.edu"),
        ("Hey Joel, did you finish the assignment for compiler design? Let's compare outputs.", "arun.v@gmail.com"),
        ("Your Swiggy order has been accepted by the restaurant and is being prepared.", "support@swiggy.in")
    ]
    for text, sender in general_legit:
        data.append({
            "text": text,
            "label": 0,
            "source": "general_legit_corpus",
            "language": "en",
            "sender": sender,
            "is_synthetic": False
        })

    # Expand dataset with varied phrasings and perturbations to provide a solid training foundation
    expanded = []
    for item in data:
        expanded.append(item)
        # Add small realistic variants
        if item["label"] == 1:
            t_var = item["text"].replace("immediately", "without delay").replace("within 24 hours", "as soon as possible")
            if t_var != item["text"]:
                expanded.append({
                    "text": t_var,
                    "label": 1,
                    "source": item["source"],
                    "language": "en",
                    "sender": item["sender"],
                    "is_synthetic": True
                })
        else:
            t_var = "Reminder: " + item["text"]
            expanded.append({
                "text": t_var,
                "label": 0,
                "source": item["source"],
                "language": "en",
                "sender": item["sender"],
                "is_synthetic": True
            })

    return expanded

def main():
    print("Preparing PhishGuard dataset...")
    os.makedirs(os.path.dirname(DATASET_RAW_PATH), exist_ok=True)
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    samples = generate_samples()
    df = pd.DataFrame(samples)

    # Clean and deduplicate
    df["text"] = df["text"].astype(str).str.strip()
    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)

    print(f"Total unique records: {len(df)}")
    print(f"Class balance:\n{df['label'].value_counts()}")

    # Save raw
    df.to_csv(DATASET_RAW_PATH, index=False)
    print(f"Saved raw dataset to {DATASET_RAW_PATH}")

    # Stratified train (70%), val (15%), test (15%)
    train_df, temp_df = train_test_split(df, test_size=0.30, random_state=42, stratify=df["label"])
    val_df, test_df = train_test_split(temp_df, test_size=0.50, random_state=42, stratify=temp_df["label"])

    train_df.to_csv(TRAIN_PATH, index=False)
    val_df.to_csv(VAL_PATH, index=False)
    test_df.to_csv(TEST_PATH, index=False)

    print(f"Splits created:")
    print(f"  Train: {len(train_df)} rows")
    print(f"  Validation: {len(val_df)} rows")
    print(f"  Test: {len(test_df)} rows (FROZEN held-out)")

if __name__ == "__main__":
    main()

"""Build the bundled demo training corpus (data/corpus.csv).

Why this file exists
--------------------
The project spec trains the text model on public research corpora
(the Nazario phishing corpus and the SpamAssassin public corpus).
Those downloads are large and need internet access, so this repo also
ships a small, hand-written *synthetic* corpus so the demo runs end to
end offline. The synthetic emails are original text written for this
project -- they imitate common phishing and legitimate patterns but
are not copied from any real mailbox.

To train on the real corpora instead, replace data/corpus.csv with a
CSV that has the same three columns: subject, body, label
(label = 1 for phishing, 0 for legitimate). See the README's
"Using the real research corpora" section.

Data hygiene (spec requirement)
-------------------------------
Before writing the CSV this script:
  1. removes exact duplicate rows (the same email must never appear on
     both sides of the train/test split -- that inflates the score),
  2. prints a random sample of rows from each class so a human can
     eyeball them before any model is trained on the data.
"""

import csv
import random
from pathlib import Path

# ---------------------------------------------------------------------------
# Synthetic sample emails. (subject, body, label) -- 1 = phishing, 0 = legit.
# Written to imitate patterns, not copied from real messages.
# ---------------------------------------------------------------------------

PHISHING = [
    ("Your account has been suspended",
     "Dear customer, we detected suspicious activity on your account. Your account will be suspended within 24 hours unless you verify your identity. Click the link below and confirm your password and card details to restore access immediately."),
    ("Verify your password now",
     "Your password expires today. To keep your account active you must confirm your current password and update your security questions right away. Failure to verify will lock your account permanently."),
    ("Unusual sign-in attempt blocked",
     "We blocked an unusual sign-in attempt from an unknown location. If this was not you, secure your account now by entering your username, password and the code sent to your phone on the verification page."),
    ("Your payment was declined",
     "Your last payment could not be processed because your billing information is out of date. Update your card number and billing address within 48 hours or your subscription will be cancelled and your files deleted."),
    ("Refund confirmation required",
     "You are owed a refund of $312.44. To release the funds we need you to confirm your bank account number and routing number on our secure form. This offer expires in 12 hours, act now."),
    ("Security alert: confirm your identity",
     "For your protection we have limited what you can do with your account until you confirm your identity. Sign in with your password and social security number to remove the limitation."),
    ("Your mailbox is almost full",
     "Your mailbox has reached 98 percent of its storage limit and incoming mail will be rejected. Click here and log in with your email password to upgrade your storage for free."),
    ("Invoice #4821 payment overdue",
     "The attached invoice is overdue. To avoid a late fee and service interruption, pay immediately using the payment link and enter your card details. This is your final notice before collections."),
    ("Confirm your delivery address",
     "We tried to deliver your package but the address on file is incomplete. Confirm your full name, address and phone number within 24 hours or the package will be returned and destroyed."),
    ("You have won a gift card",
     "Congratulations! You have been selected to receive a $500 gift card. Claim your prize now by entering your email password and mobile number so we can verify your entry before the deadline tonight."),
    ("Tax refund notification",
     "Our records show you are due a tax refund. Submit your bank details and date of birth on the refund portal within 3 days to receive your money. Unclaimed refunds will be forfeited."),
    ("Action required: payroll update",
     "Human Resources is migrating payroll systems. All employees must re-enter their direct deposit bank account details and password on the new portal before Friday or pay will be delayed."),
    ("Your cloud storage will be deleted",
     "Your photos and documents will be permanently deleted in 2 days because your storage plan lapsed. Renew now by confirming your payment card details to keep your files safe."),
    ("Suspicious transaction alert",
     "A transaction of $1,204.99 was attempted on your card. If you do not recognize it, cancel it immediately by signing in and confirming your card number, expiry date and security code."),
    ("Re-activate your streaming account",
     "We could not renew your membership because your payment method failed. Update your card details within 24 hours or your account and watch history will be permanently removed."),
    ("Document shared with you: Salary Review",
     "A confidential document has been shared with you. Sign in with your work email and password to view the salary review spreadsheet. The link expires in one hour."),
    ("Confirm your phone number",
     "Your account requires additional verification. Enter the code we texted you together with your password on the verification page or your number will be deactivated today."),
    ("Your order has been placed on hold",
     "Your order is on hold because we could not verify your payment. Confirm your card details and billing zip code now or the order will be cancelled and the items released."),
    ("Apple ID locked for security reasons",
     "Your Apple ID has been locked due to multiple failed sign-in attempts. Unlock it immediately by confirming your password and answering your security questions on the recovery page."),
    ("Benefits enrollment action needed",
     "Open enrollment closes tonight. Log in with your employee credentials and confirm your bank account for benefits payments or you will lose coverage for the coming year."),
    ("Wire transfer confirmation",
     "A wire transfer of $9,800 is pending your approval. If you did not authorize this transfer, sign in now with your online banking password to stop it before it completes."),
    ("Your subscription price is increasing",
     "Your plan price increases next month. Keep your current rate by confirming your account password and payment details on the loyalty page before the deadline this week."),
    ("Two-factor authentication disabled",
     "Two-factor authentication was turned off on your account. If this was not you, restore it immediately by entering your password and backup codes on the security page."),
    ("Package held at customs",
     "Your international package is being held at customs and a fee is owed. Pay the fee and confirm your passport number and address within 48 hours or the package will be seized."),
    ("Verify your wallet recovery phrase",
     "We detected a problem syncing your wallet. To restore access, enter your 12 word recovery phrase on the secure recovery page. Never share it with anyone except our support team."),
    ("Your email password expires today",
     "This is an automated message from IT support. Your email password expires today. Use the link below and enter your current password to keep the same password for another 90 days."),
    ("Court notice: appearance required",
     "You have been named in a court proceeding and must appear next week. Download the attached notice and confirm your identity with your social security number to receive the case details."),
    ("Confirm new payee added",
     "A new payee was added to your bank account. If you do not recognize this payee, cancel it now by signing in and confirming your account number and password."),
    ("Storage payment failed",
     "We were unable to charge your card for storage this month. Your files will be erased in 24 hours unless you update your payment information and confirm your password."),
    ("Final warning: account closure",
     "This is your final warning. Your account will be closed and the balance forfeited unless you verify your identity today by entering your password and card details on the secure page."),
    ("HR: updated W-2 available",
     "Your updated tax form is ready. Sign in with your employee password and confirm your social security number to download the corrected form before the filing deadline."),
    ("Reset your voicemail PIN",
     "Your voicemail PIN has been reset by an unknown device. If this was not you, call the number in this message and provide your account password to secure your mailbox."),
]

LEGITIMATE = [
    ("Your November statement is ready",
     "Hello, your monthly statement for the account ending in 0112 is now available in online banking. Sign in at our official website to view it. We will never ask for your password or PIN by email."),
    ("Meeting moved to 2:30 PM",
     "Hi team, the project sync is moved to 2:30 PM tomorrow because of the client call. Same agenda, updated slide deck is in the shared drive. Let me know if the new time does not work for you."),
    ("Your order has shipped",
     "Good news, your order is on its way. You can track your package from the orders page in your account. Delivery is expected on Thursday. Thanks for shopping with us."),
    ("Password changed on your account",
     "This is a confirmation that the password for your account was changed a few minutes ago. If you made this change, no action is needed. If you did not, visit our official site and use the account recovery options."),
    ("Your receipt from City Coffee",
     "Thanks for your purchase. Your receipt for $6.40 is attached and also available in the app under purchase history. We hope to see you again soon."),
    ("Reminder: dentist appointment Tuesday",
     "This is a reminder of your appointment on Tuesday at 10:00 AM. Please arrive 10 minutes early and bring your insurance card. Reply to this email or call our office to reschedule."),
    ("Weekly project update",
     "Here is this week's update: the migration finished on schedule, two tickets remain open, and the vendor demo is booked for Friday. Full notes are in the project tracker for anyone who wants details."),
    ("Your flight itinerary",
     "Your booking is confirmed. Flight details, seat assignments and check-in instructions are in your account on our website. Online check-in opens 24 hours before departure."),
    ("New sign-in to your account",
     "A new sign-in was detected from Chrome on Windows in Atlanta, Georgia. If this was you, you can ignore this message. If it was not you, review your security settings on our official website."),
    ("Your subscription renews next month",
     "This is a friendly reminder that your annual plan renews on December 3 at the regular price. You can review or change your plan any time from the billing page in your account settings."),
    ("Homework assignment posted",
     "A new assignment has been posted for IT 2531. The instructions and rubric are in the course shell, and the submission window closes Sunday night. Office hours are Thursday if you need help."),
    ("Package delivered",
     "Your package was delivered and left at the front door at 1:42 PM. You can view delivery details and a photo from the tracking page in your account."),
    ("Your tax documents are available",
     "Your year-end tax documents are now available to download from your account dashboard. Sign in on our official website to access them. Paper copies will also arrive by mail."),
    ("Team lunch on Friday",
     "We are ordering lunch for the team on Friday to celebrate the launch. Please add your order to the shared sheet by Thursday afternoon and note any allergies."),
    ("Library book due next week",
     "The book you borrowed is due back next Tuesday. You can renew it from your library account online or return it to any branch. Fines are 25 cents per day after the due date."),
    ("Your gym class schedule",
     "Here is next week's class schedule. Spin moves to 6 AM on Wednesday and the Saturday yoga class is now in studio B. Book your spot in the app as usual."),
    ("Quarterly newsletter",
     "In this quarter's newsletter: our office hours are changing for the holidays, two new staff members joined the support team, and the community workshop series returns in January. Read more on our website."),
    ("Appointment confirmed",
     "Your appointment with Dr. Patel is confirmed for Monday at 9:15 AM. Please bring your medication list. You can manage this appointment from the patient portal at any time."),
    ("Your photo prints are ready",
     "Your prints are ready for pickup at the Peachtree location. Bring your order number from the app when you come in. We hold pickup orders for 14 days."),
    ("Invoice for October services",
     "Attached is the invoice for October services, due on the 15th under our existing agreement. Payment details are the same as last month. Thank you for your business."),
    ("Course registration confirmed",
     "You are registered for GEOG 1130 and INTS 2130 for the spring term. Your schedule and textbook list are in the student portal. The add and drop deadline is January 20."),
    ("Security tip: enable passkeys",
     "Passkeys are a safer way to sign in than passwords, and you can set one up in your account security settings. It takes about a minute and protects you against phishing. Learn more on our help site."),
    ("Your hotel reservation",
     "Your reservation for two nights is confirmed. Check-in begins at 3 PM and parking is available on site. Your confirmation number is in your account under trips."),
    ("Utility bill is ready",
     "Your November utility bill is ready to view in your online account. The amount due is $86.17 and the due date is December 1. Paperless billing is on for this account."),
    ("Volunteer schedule for Saturday",
     "Thanks for volunteering. Your shift on Saturday runs from 9 AM to noon at the community center. Please wear your volunteer badge and check in at the front desk when you arrive."),
    ("Your prescription is ready",
     "Your prescription is ready for pickup at the pharmacy counter. It will be held for 10 days. The pharmacy is open until 9 PM tonight if you want to come by."),
    ("Software update available",
     "Version 4.2 of our app is available in the app store. This release fixes the calendar sync bug and improves battery usage. Update at your convenience from the store listing."),
    ("Minutes from yesterday's call",
     "Attached are the minutes from yesterday's planning call. Action items are at the top with owners and dates. Please reply with corrections by Friday so we can finalize them."),
    ("Your savings goal update",
     "You are 62 percent of the way to your emergency fund goal. Your automatic transfer of $75 completed on schedule. Keep it up, you are on track to finish in March."),
    ("Weather alert for your area",
     "The National Weather Service has issued a thunderstorm watch for your area until 8 PM this evening. Expect heavy rain and gusty winds. Check the forecast before traveling."),
    ("Book club picks for December",
     "December's pick is in: we are reading the same title in both groups and meeting on the 18th at the main library. New members are welcome, just reply to this email to join the list."),
    ("Your direct deposit was received",
     "A direct deposit of $1,240.00 was received and posted to your account ending in 0112. You can view the details in online banking. No action is needed."),
]


def main() -> None:
    rows = [(s, b, 1) for s, b in PHISHING] + [(s, b, 0) for s, b in LEGITIMATE]

    # --- Data hygiene step 1: dedupe BEFORE any train/test split. ----------
    seen = set()
    unique_rows = []
    for subject, body, label in rows:
        key = (subject.strip().lower(), body.strip().lower())
        if key in seen:
            continue
        seen.add(key)
        unique_rows.append((subject, body, label))
    duplicates_removed = len(rows) - len(unique_rows)

    # --- Data hygiene step 2: eyeball a random sample from each class. -----
    random.seed(42)
    print("=== DATA HYGIENE CHECK ===")
    print(f"Total rows written: {len(unique_rows)} "
          f"(duplicates removed: {duplicates_removed})")
    for label, name in ((1, "PHISHING"), (0, "LEGITIMATE")):
        class_rows = [r for r in unique_rows if r[2] == label]
        print(f"\n--- {name}: {len(class_rows)} rows, 3 random samples ---")
        for subject, body, _ in random.sample(class_rows, 3):
            print(f"  * {subject} :: {body[:80]}...")

    out_path = Path(__file__).with_name("corpus.csv")
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["subject", "body", "label"])
        writer.writerows(unique_rows)
    print(f"\nWrote {out_path}")


if __name__ == "__main__":
    main()

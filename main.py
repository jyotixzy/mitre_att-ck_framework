# Purpose: Yeh project ka sabse top-level entry point hai.
# User terminal se jo command chalata hai, woh sabse pehle isi file me aati hai.
# Is file ka kaam sirf CLI module ko start karna hai, taaki main logic alag modules me clean rahe.

from url_analyzer.cli import main


if __name__ == "__main__":
    main()

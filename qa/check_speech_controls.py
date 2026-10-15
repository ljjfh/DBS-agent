"""Exercise speech controls in Edge with deterministic speech events (no audio/cloud)."""
from playwright.sync_api import sync_playwright
from pathlib import Path
import run_extended as q


def main():
    server, thread, base = q.start_http()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="msedge", headless=True)
        context = browser.new_context()
        context.add_init_script("""
          window.spoken = []; window.pauses = 0; window.resumes = 0;
          speechSynthesis.speak = u => { spoken.push(u); u.onstart?.(); };
          speechSynthesis.pause = () => { pauses++; spoken.at(-1)?.onpause?.(); };
          speechSynthesis.resume = () => { resumes++; spoken.at(-1)?.onresume?.(); };
          speechSynthesis.cancel = () => {};
        """)
        page = context.new_page()
        # Expose module-local controls only in this isolated test response.
        source = (Path(__file__).resolve().parents[1] / 'web' / 'app.js').read_text(encoding='utf-8')
        source += '\nObject.assign(window, {stopSpeaking, state, push, speak, renderStage});'
        page.route('**/app.js*', lambda route: route.fulfill(body=source, content_type='application/javascript'))
        page.goto(base.replace("127.0.0.1", "localhost"))
        page.locator("#welcome-enter").click()
        page.locator("#welcome").wait_for(state="hidden")
        page.wait_for_selector("#text")
        page.evaluate("""() => {
          stopSpeaking(); state.messages = []; state.readAloud = true;
          push({role:'bot', text:'First answer'});
          speak('A longer spoken version of the first answer');
        }""")
        button = page.locator(".replay").first
        assert button.get_attribute("aria-label") == "Pause reading"
        count = page.evaluate("spoken.length")
        button.click()
        assert button.get_attribute("aria-label") == "Resume reading"
        page.evaluate("renderStage()")
        assert button.get_attribute("aria-label") == "Resume reading"
        button.click()
        assert button.get_attribute("aria-label") == "Pause reading"
        assert page.evaluate("spoken.length") == count  # resume, never restart
        page.evaluate("spoken.at(-1).onend()")
        assert button.get_attribute("aria-label") == "Read this aloud"
        button.click()
        assert page.evaluate("spoken.length") == count + 1
        assert page.evaluate("spoken.at(-1).text") == "First answer"
        page.evaluate("push({role:'bot', text:'Second answer'})")
        page.locator(".replay").nth(1).click()
        assert button.get_attribute("aria-label") == "Read this aloud"
        assert page.locator(".replay").nth(1).get_attribute("aria-label") == "Pause reading"
        page.evaluate("spoken.at(-2).onend()")  # stale event must not clear new reading
        assert page.locator(".replay").nth(1).get_attribute("aria-label") == "Pause reading"
        page.evaluate("spoken.at(-1).onerror()")
        assert page.locator(".replay").nth(1).get_attribute("aria-label") == "Read this aloud"
        page.evaluate("""() => {
          speak('First', true, state.messages[0]); state.queueSpeech = true;
          speak('Second', true, state.messages[1]);
        }""")
        assert button.get_attribute("aria-label") == "Pause reading"
        page.evaluate("spoken.at(-2).onend()")
        assert page.locator(".replay").nth(1).get_attribute("aria-label") == "Pause reading"
        page.locator(".replay").nth(1).click()
        page.evaluate("stopSpeaking()")
        assert page.get_by_role("button", name="Resume reading").count() == 0
        assert page.get_by_role("button", name="Pause reading").count() == 0
        browser.close()
    server.should_exit = True
    thread.join(timeout=5)
    print("PASS: automatic speech association, pause/resume, rerender, replay, switching, stale events, errors, queue, stop")


if __name__ == "__main__":
    main()

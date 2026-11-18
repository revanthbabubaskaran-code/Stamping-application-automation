"""Local regression fixture; no requests to the Labour portal."""
import queue
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / '.build-deps'))
from playwright.sync_api import sync_playwright
from stamping_assistant import PortalWorker


def test_repeated_identifiers(certificate=None):
    if certificate:
        from stamping_assistant import extract_certificate_document
        _, _, _, machines = extract_certificate_document(certificate)
    else:
        machines = [{'Application number': str(1907563 + i),
                     'Previous CV number': f'SLM/547/{44633+i:06d}'} for i in range(3)]
    rows = []
    for i in range(len(machines)):
        rows.append(f'''<div class="record">
        <label>Online/Other State<select><option value="online">Online</option></select></label>
        <label for="date{i}">Certificate Date</label><input id="date{i}" readonly>
        <label for="app{i}">Application Number</label><input id="app{i}">
        <label for="cv{i}">Certificate Number</label><input id="cv{i}">
        <button>{'Add' if i == 0 else 'Delete'}</button></div>''')
    html = '<section><h3>Previous Information</h3>' + ''.join(rows) + '''</section>
    <script>document.addEventListener('change', e => {
      const row = e.target.closest('.record');
      if (!row) return;
      const inputs = row.querySelectorAll('input');
      if(inputs[1].value && inputs[2].value) inputs[0].value='30-12-2025';
    });</script>'''
    with sync_playwright() as pw:
        chrome = next((ROOT / '.pw-browsers').glob('chromium-*/chrome-win64/chrome.exe'))
        browser = pw.chromium.launch(executable_path=str(chrome), headless=True)
        page = browser.new_page()
        page.set_content(html)
        worker = PortalWorker(queue.Queue())
        worker.page = page
        for attempt in range(2):
            skipped, filled = [], []
            worker._fill_items_and_previous_information([], machines, skipped, filled)
            assert not skipped, skipped
            for i, machine in enumerate(machines):
                assert page.locator(f'#app{i}').input_value() == machine['Application number']
                assert page.locator(f'#cv{i}').input_value() == machine['Previous CV number']
                assert page.locator(f'#date{i}').input_value() == '30-12-2025'
            assert page.locator('.record').count() == len(machines)
        browser.close()
    print(f'PASS: {len(machines)} certificate/application pairs, dates, and repeat attempt')


def test_online_only_model_fallback():
    """A stale Model Name row may rerender with only Online/Other State."""
    from stamping_assistant import PortalWorker
    html = '''
    <section>
      <h3>Previous Information</h3>
      <div class="record">
        <label>Online/Other State<select id="state0"><option value="">Select</option><option value="online">Online</option><option value="other">Other State</option></select></label>
        <label>Certificate Date<input id="date0" readonly></label>
        <label>Application Number<input id="app0"></label>
        <label>Certificate Number<input id="cv0"></label>
        <button id="add">Add</button>
      </div>
    </section>
    <script>
      document.querySelector('#add').addEventListener('click', () => {
        const row = document.createElement('div'); row.className = 'record';
        row.innerHTML = `<label>Model Name<select id="state1"><option value="">Select</option><option value="loading">Loading</option></select></label>
          <label>Certificate Date<input id="date1" readonly></label>
          <label>Application Number<input id="app1"></label>
          <label>Certificate Number<input id="cv1"></label>
          <button>Delete</button>`;
        document.querySelector('section').append(row);
        setTimeout(() => {
          const select = document.querySelector('#state1');
          select.innerHTML = '<option value="">Select</option><option value="online">Online</option><option value="other">Other State</option>';
        }, 100);
      });
      document.addEventListener('change', e => {
        if (e.target.id === 'state1' && e.target.value === 'online') {
          const label = e.target.closest('label'); label.firstChild.textContent = 'Online/Other State';
        }
        const row = e.target.closest('.record'); if (!row) return;
        const app = row.querySelector('[id^="app"]'), cv = row.querySelector('[id^="cv"]');
        if (app.value && cv.value) row.querySelector('[id^="date"]').value = '30-12-2025';
      });
    </script>'''
    machines = [
        {'Application number': '1899952', 'Previous CV number': 'SLM/74/043335', 'Instrument description': 'Non-Automatic Weighing Instruments - Electronic Class III and IIII'},
        {'Application number': '1899952', 'Previous CV number': 'SLM/74/043334', 'Instrument description': 'Non-Automatic Weighing instruments both mechanical and electronics Class I and II'},
    ]
    with sync_playwright() as pw:
        chrome = next((ROOT / '.pw-browsers').glob('chromium-*/chrome-win64/chrome.exe'))
        browser = pw.chromium.launch(executable_path=str(chrome), headless=True)
        page = browser.new_page()
        page.set_content(html)
        worker = PortalWorker(queue.Queue())
        worker.page = page
        skipped, filled = [], []
        worker._fill_items_and_previous_information([], machines, skipped, filled)
        assert not skipped, skipped
        assert page.locator('#state1').input_value() == 'online'
        for i, machine in enumerate(machines):
            assert page.locator(f'#app{i}').input_value() == machine['Application number']
            assert page.locator(f'#cv{i}').input_value() == machine['Previous CV number']
            assert page.locator(f'#date{i}').input_value() == '30-12-2025'
        browser.close()
    print('PASS: Online-only fallback selected Online and filled both identifiers/date')


if __name__ == '__main__':
    test_repeated_identifiers(sys.argv[1] if len(sys.argv) > 1 else None)
    test_online_only_model_fallback()


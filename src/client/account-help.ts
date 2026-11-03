export function initAccountHelp(root: HTMLElement) {
  for (const help of root.querySelectorAll<HTMLElement>(".acct-help")) {
    const button = help.querySelector<HTMLButtonElement>("button")!;
    const tip = help.querySelector<HTMLElement>(".info-tip")!;
    let timer: ReturnType<typeof setTimeout>;
    const hide = () => {
      clearTimeout(timer);
      if (tip.matches(":popover-open")) tip.hidePopover();
    };
    const show = () => {
      clearTimeout(timer);
      if (tip.matches(":popover-open")) return;
      tip.showPopover();
      tip.style.left = "0px";
      tip.style.top = "0px";
      tip.style.maxWidth = "";
      const scale = tip.getBoundingClientRect().width / tip.offsetWidth;
      tip.style.maxWidth = `${Math.min(320, (innerWidth - 16) / scale)}px`;
      const box = tip.getBoundingClientRect();
      const anchor = button.getBoundingClientRect();
      const left = Math.max(8, Math.min(anchor.left, innerWidth - box.width - 8));
      const top = anchor.bottom + box.height + 8 <= innerHeight
        ? anchor.bottom + 6 : Math.max(8, anchor.top - box.height - 6);
      tip.style.left = `${(left - box.left) / scale}px`;
      tip.style.top = `${(top - box.top) / scale}px`;
    };
    const leave = () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        if (!help.matches(":hover") && document.activeElement !== button) hide();
      }, 150);
    };
    help.addEventListener("pointerenter", (e) => { if (e.pointerType !== "touch") show(); });
    help.addEventListener("pointerleave", leave);
    button.addEventListener("focus", show);
    button.addEventListener("blur", leave);
    button.addEventListener("click", show);
    tip.addEventListener("toggle", () => {
      button.setAttribute("aria-expanded", String(tip.matches(":popover-open")));
    });
    root.addEventListener("scroll", hide);
    window.addEventListener("resize", hide);
  }
}

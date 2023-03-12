<script>
    export let warning = false;

    import { createEventDispatcher } from "svelte";

    const dispatch = createEventDispatcher();
</script>

<a
    href="#!"
    on:click|preventDefault={() => {
        dispatch("click");
    }}
>
    <div class="card-panel {warning ? 'orange' : 'grey lighten-4'} hoverable">
        <span class={warning ? "white-text" : "black-text"}>
            <i class="material-icons">{warning ? "warning" : "info"}</i>
            <slot />
        </span>
    </div>
</a>

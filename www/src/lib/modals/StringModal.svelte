<script>
    export let textSelected = false;

    import { createEventDispatcher, onMount } from "svelte";
    import { selectText } from "../utils";

    const dispatch = createEventDispatcher();

    let modal;
    let content;

    onMount(() => {
        window.M.Modal.init(modal, {
            onCloseEnd: () => dispatch("close"),
        }).open();
        if (textSelected) {
            selectText(content);
        }
    });

    const handleCloseClick = (e) => {
        // We need to do this ourselves, so that
        // we don't drag the CertModal down with
        // us when this is on top of that.
        window.M.Modal.getInstance(modal).close();
    };
</script>

<div id="string-modal" class="modal string-modal" bind:this={modal}>
    <div class="modal-content">
        <div class="right">
            <button
                class="modal-action waves-effect waves-green btn-flat"
                on:click={handleCloseClick}
            >
                <i class="material-icons">close</i>
            </button>
        </div>
        <div bind:this={content}>
            <slot />
        </div>
    </div>
</div>

<style>
    /*
    When used to show the ldap url,
    we're inside a right-align block,
    so need to override that.
    */
    .string-modal {
        text-align: left;
    }
</style>

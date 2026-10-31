<?php
class Evil {
    public $cmd;
    public function __destruct() {
        if ($this->cmd) {
            file_put_contents("/tmp/e_proof", shell_exec($this->cmd));
        }
    }
}

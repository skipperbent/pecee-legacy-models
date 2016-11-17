<?php
namespace Pecee\Models\Legacy\File;

use Carbon\Carbon;
use Pecee\Guid;
use Pecee\Models\Legacy\ModelData;

class ModelFile extends ModelData {

	const ORDER_DATE_ASC = 'f.`created_at` ASC';
	const ORDER_DATE_DESC = 'f.`created_at` DESC';

	public static $ORDERS = array(self::ORDER_DATE_ASC, self::ORDER_DATE_DESC);

    protected $table = 'file';

    protected $timestamps = true;

    protected $columns = [
        'id',
        'filename',
        'original_filename',
        'path',
        'type',
        'bytes',
    ];

	public function __construct($file) {

		parent::__construct();

        $this->id = Guid::create();
        $this->filename = basename($file);
        $this->original_filename = basename($file);
        $this->path = dirname($file);

        if(is_file($file)) {
            $this->type = mime_content_type($file);
            $this->bytes = filesize($file);
        }
	}

	public function setFilename($filename) {
		$this->filename = $filename;
	}

	public function setOriginalFilename($filename) {
		$this->original_filename = $filename;
	}

	public function setPath($path) {
		$this->path = rtrim($path, DIRECTORY_SEPARATOR);
	}

	public function setType($type) {
		$this->type = $type;
	}

	public function setBytes($bytes) {
		$this->bytes = $bytes;
	}

	public function setCreatedAt(Carbon $date) {
		$this->created_at = $date->toDateTimeString();
	}

	public function updateData() {
		if($this->data) {
			/* Remove all fields */
			FileData::removeAll($this->id);
			foreach($this->data->getData() as $key=>$value) {
				$data  =new FileData($this->id, $key, $value);
				$data->save();
			}
		}
	}

	protected function fetchData() {
		$data = FileData::getByFileId($this->id);
		if($data->hasRows()) {
			foreach($data->getRows() as $d) {
				$this->setDataValue($d->key, $d->value);
			}
		}
	}

	public function getFullPath() {
		return $this->path . $this->Filename;
	}

	/**
	 * Get file by file id.
	 * @param string $id
	 * @return static
	 */
	public static function getById($id){
		return self::fetchOne('SELECT * FROM {table} WHERE `id` = %s', array($id));
	}

	public static function get($order=null, $rows=null, $page=null){
		$order = (in_array($order, self::$ORDERS)) ? $order : self::ORDER_DATE_DESC;
		return self::fetchPage('SELECT f.* FROM {table} f ORDER BY ' .$order, $rows,$page);
	}
}